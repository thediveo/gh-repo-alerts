// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/briandowns/spinner"
	"github.com/cli/go-gh/v2/pkg/api"
)

const (
	perPage        = 100
	requestTimeout = 30 * time.Second
	alertWorkers   = 4
	progressEvery  = 5

	ansiReset   = "\033[0m"
	ansiBold    = "\033[1m"
	ansiCursive = "\033[3m"

	ansiCyan   = "\033[36m"
	ansiYellow = "\033[33m"
	ansiRed    = "\033[31m"
	ansiGray   = "\033[90m"
	ansiWhite  = "\033[97m"

	ansiCriticalBg = "\033[41m"

	spinnerDelay = 120 * time.Millisecond
)

var spinnerDots = []string{"⠉", "⠘", "⠰", "⢠", "⣀", "⡄", "⠆", "⠃"}

type User struct {
	Login string `json:"login"`
}

type Repository struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Archived bool   `json:"archived"`

	Owner struct {
		Login string `json:"login"`
	} `json:"owner"`
}

type Alert struct {
	Number int `json:"number"`

	Dependency struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
	} `json:"dependency"`

	SecurityAdvisory struct {
		GHSAID  string `json:"ghsa_id"`
		Summary string `json:"summary"`
	} `json:"security_advisory"`

	SecurityVulnerability struct {
		Severity string `json:"severity"`
	} `json:"security_vulnerability"`
}

type repoAlerts struct {
	Repo   Repository
	Alerts []Alert
	Err    error
}

func newSpinner(message string) *spinner.Spinner {
	s := spinner.New(spinnerDots, spinnerDelay, spinner.WithWriter(os.Stderr))
	s.Suffix = " " + message
	s.Start()
	return s
}

// requestError preserves the HTTP status when go-gh returns an
// error for a non-successful API response.
type requestError struct {
	StatusCode int
	Err        error
}

func (e *requestError) Error() string {
	return e.Err.Error()
}

func (e *requestError) Unwrap() error {
	return e.Err
}

func request(ctx context.Context, client *api.RESTClient, path string) ([]byte, http.Header, error) {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	resp, err := client.RequestWithContext(reqCtx, http.MethodGet, path, nil)

	if err != nil {
		if resp != nil {
			defer func() { _ = resp.Body.Close() }()

			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				return nil, resp.Header, readErr
			}
			return body, resp.Header, &requestError{
				StatusCode: resp.StatusCode,
				Err:        err,
			}
		}
		return nil, nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.Header, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return body, resp.Header, &requestError{
			StatusCode: resp.StatusCode,
			Err:        fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode),
		}
	}

	return body, resp.Header, nil
}

func nextLink(header string) string {
	for part := range strings.SplitSeq(header, ",") {
		part = strings.TrimSpace(part)

		if !strings.Contains(part, `rel="next"`) {
			continue
		}

		start := strings.IndexByte(part, '<')
		end := strings.IndexByte(part, '>')

		if start >= 0 && end > start {
			return part[start+1 : end]
		}
	}

	return ""
}

func getUser(ctx context.Context, client *api.RESTClient) (*User, error) {
	body, _, err := request(ctx, client, "user")
	if err != nil {
		return nil, err
	}

	var user User
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("decode user: %w", err)
	}

	if user.Login == "" {
		return nil, errors.New("GitHub returned an empty login")
	}

	return &user, nil
}

func getRepositories(ctx context.Context, client *api.RESTClient) ([]Repository, error) {
	var repos []Repository

	path := fmt.Sprintf("user/repos?affiliation=owner,collaborator,organization&per_page=%d&sort=full_name&direction=asc",
		perPage)

	for path != "" {
		body, headers, err := request(ctx, client, path)
		if err != nil {
			return nil, fmt.Errorf("list repositories: %w", err)
		}

		var page []Repository
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("decode repositories: %w", err)
		}

		repos = append(repos, page...)
		path = nextLink(headers.Get("Link"))
	}

	return repos, nil
}

func getAlerts(ctx context.Context, client *api.RESTClient, owner string, repo string) ([]Alert, error) {
	path := fmt.Sprintf("repos/%s/%s/dependabot/alerts?state=open&per_page=%d",
		owner, repo, perPage)

	var alerts []Alert

	for path != "" {
		body, headers, err := request(ctx, client, path)

		if err != nil {
			// GitHub returns HTTP 403 with this message when
			// Dependabot alerts are disabled for the repository.
			//
			// This is an expected condition, so silently skip it.
			if httpErr, ok := errors.AsType[*api.HTTPError](err); ok {
				if strings.Contains(httpErr.Error(), "Dependabot alerts are disabled for this repository") {
					return nil, nil
				}
			}

			return nil, fmt.Errorf("get Dependabot alerts: %w", err)
		}

		var page []Alert

		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("decode alerts for %s/%s: %w", owner, repo, err)
		}

		alerts = append(alerts, page...)
		path = nextLink(headers.Get("Link"))
	}

	return alerts, nil
}

func severityRank(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	default:
		return 4
	}
}

func sortAlerts(alerts []Alert) {
	sort.SliceStable(alerts, func(i, j int) bool {
		severityI := severityRank(alerts[i].SecurityVulnerability.Severity)
		severityJ := severityRank(alerts[j].SecurityVulnerability.Severity)

		if severityI != severityJ {
			return severityI < severityJ
		}

		return alerts[i].Number < alerts[j].Number
	})
}

func alertURL(repo string, number int) string {
	return fmt.Sprintf("https://github.com/%s/security/dependabot/%d",
		repo, number)
}

func printAlert(repo string, alert Alert) {
	severity := strings.ToUpper(alert.SecurityVulnerability.Severity)

	severityStyle := ansiBold
	severityLabel := severity

	switch severity {
	case "LOW":
		severityStyle = ansiBold + ansiCyan
	case "MEDIUM":
		severityStyle = ansiBold + ansiYellow
	case "HIGH":
		severityStyle = ansiBold + ansiRed
	case "CRITICAL":
		severityStyle = ansiBold + ansiWhite + ansiCriticalBg
		severityLabel = "⚠ CRITICAL"
	}

	if alert.SecurityAdvisory.Summary != "" {
		fmt.Printf("  [%s%s%s] %s%s%s\n",
			severityStyle, severityLabel, ansiReset,
			ansiCursive, alert.SecurityAdvisory.Summary, ansiReset,
		)
	} else {
		fmt.Printf("  [%s%s%s]\n",
			severityStyle, severityLabel, ansiReset)
	}

	fmt.Printf("      %s %s%s\n",
		ansiGray, alert.Dependency.Package.Name, ansiReset)

	fmt.Printf("      %s󱝾 %s%s\n",
		ansiGray, alertURL(repo, alert.Number), ansiReset)
}

func getAlertsInParallel(ctx context.Context, client *api.RESTClient, repos []Repository) []repoAlerts {
	results := make([]repoAlerts, len(repos))

	if len(repos) == 0 {
		return results
	}

	// Buffer all jobs so the coordinator never blocks while workers
	// are reporting completion.
	jobs := make(chan int, len(repos))
	done := make(chan struct{})

	workerCount := min(alertWorkers, len(repos))

	var wg sync.WaitGroup
	wg.Add(workerCount)

	for range workerCount {
		go func() {
			defer wg.Done()

			for i := range jobs {
				if ctx.Err() != nil {
					return
				}

				repo := repos[i]
				alerts, err := getAlerts(ctx, client, repo.Owner.Login, repo.Name)
				results[i] = repoAlerts{
					Repo:   repo,
					Alerts: alerts,
					Err:    err,
				}
				select {
				case done <- struct{}{}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Queue all repositories. The channel is buffered, so this does
	// not block waiting for workers to consume jobs.
	for i := range repos {
		select {
		case jobs <- i:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return results
		}
	}
	close(jobs)

	s := newSpinner(fmt.Sprintf("Checking repositories: 0/%d processed (%d parallel queries)",
		len(repos), workerCount))
	go func() {
		wg.Wait()
		close(done)
	}()
	processed := 0
	for range done {
		processed++
		if processed%progressEvery == 0 || processed == len(repos) {
			s.Suffix = fmt.Sprintf(" Checking repositories: %d/%d processed (%d parallel queries)",
				processed, len(repos), workerCount)
		}
	}
	s.Stop()

	return results
}

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	client, err := api.DefaultRESTClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating GitHub client: %v\n", err)
		os.Exit(1)
	}

	s := newSpinner("Getting GitHub user")
	user, err := getUser(ctx, client)
	s.Stop()

	if err != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, "Interrupted.")
			os.Exit(130)
		}

		fmt.Fprintf(os.Stderr, "error getting user: %v\n", err)
		os.Exit(1)
	}

	s = newSpinner(fmt.Sprintf("Getting repositories for %s", user.Login))
	repos, err := getRepositories(ctx, client)
	s.Stop()

	if err != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, "Interrupted.")
			os.Exit(130)
		}

		fmt.Fprintf(os.Stderr, "error getting repositories: %v\n", err)
		os.Exit(1)
	}

	activeRepos := make([]Repository, 0, len(repos))
	for _, repo := range repos {
		if repo.Archived {
			continue
		}

		activeRepos = append(activeRepos, repo)
	}
	results := getAlertsInParallel(ctx, client, activeRepos)

	if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "Interrupted.")
		os.Exit(130)
	}

	for _, result := range results {
		if result.Err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s: %v\n",
				result.Repo.FullName, result.Err)
			continue
		}

		if len(result.Alerts) == 0 {
			continue
		}

		sortAlerts(result.Alerts)

		fmt.Printf(" %s%s%s: %d open alerts\n",
			ansiBold, result.Repo.FullName, ansiReset, len(result.Alerts))

		for _, alert := range result.Alerts {
			printAlert(result.Repo.FullName, alert)
		}

		fmt.Println()
	}

	fmt.Fprintln(os.Stderr, "Done.")
}
