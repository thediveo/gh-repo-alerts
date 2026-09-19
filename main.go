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
	"strings"
	"syscall"
	"time"

	"github.com/briandowns/spinner"
	"github.com/cli/go-gh/v2/pkg/api"
)

const (
	perPage        = 100
	requestTimeout = 30 * time.Second

	ansiReset      = "\033[0m"
	ansiBold       = "\033[1m"
	ansiUnderline  = "\033[4m"
	ansiCyan       = "\033[36m"
	ansiBrightCyan = "\033[96m"
	ansiYellow     = "\033[33m"
	ansiRed        = "\033[31m"
	ansiCriticalBg = "\033[41m"
	ansiWhite      = "\033[97m"

	spinnerDelay = 80 * time.Millisecond
)

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

func newSpinner(message string) *spinner.Spinner {
	s := spinner.New(
		spinner.CharSets[14],
		spinnerDelay,
		spinner.WithWriter(os.Stderr),
	)

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

func request(
	ctx context.Context,
	client *api.RESTClient,
	path string,
) ([]byte, http.Header, int, error) {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	resp, err := client.RequestWithContext(
		reqCtx,
		http.MethodGet,
		path,
		nil,
	)

	if err != nil {
		if resp != nil {
			defer resp.Body.Close()

			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				return nil, resp.Header, resp.StatusCode, readErr
			}

			return body, resp.Header, resp.StatusCode,
				&requestError{
					StatusCode: resp.StatusCode,
					Err:        err,
				}
		}

		return nil, nil, 0, err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.Header, resp.StatusCode, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return body, resp.Header, resp.StatusCode,
			&requestError{
				StatusCode: resp.StatusCode,
				Err: fmt.Errorf(
					"GitHub API returned HTTP %d",
					resp.StatusCode,
				),
			}
	}

	return body, resp.Header, resp.StatusCode, nil
}

func nextLink(header string) string {
	for _, part := range strings.Split(header, ",") {
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

func getUser(
	ctx context.Context,
	client *api.RESTClient,
) (*User, error) {
	body, _, _, err := request(ctx, client, "user")
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

func getRepositories(
	ctx context.Context,
	client *api.RESTClient,
) ([]Repository, error) {
	var repos []Repository

	path := fmt.Sprintf(
		"user/repos?affiliation=owner,collaborator,organization&per_page=%d&sort=full_name&direction=asc",
		perPage,
	)

	for path != "" {
		body, headers, _, err := request(ctx, client, path)

		if err != nil {
			return nil, fmt.Errorf(
				"list repositories: %w",
				err,
			)
		}

		var page []Repository

		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf(
				"decode repositories: %w",
				err,
			)
		}

		repos = append(repos, page...)

		path = nextLink(headers.Get("Link"))
	}

	return repos, nil
}

func getAlerts(
	ctx context.Context,
	client *api.RESTClient,
	owner string,
	repo string,
) ([]Alert, error) {
	path := fmt.Sprintf(
		"repos/%s/%s/dependabot/alerts?state=open&per_page=%d",
		owner,
		repo,
		perPage,
	)

	var alerts []Alert

	for path != "" {
		body, headers, _, err := request(
			ctx,
			client,
			path,
		)

		if err != nil {
			// GitHub returns HTTP 403 with this message when
			// Dependabot alerts are disabled for the repository.
			//
			// This is an expected condition, so silently skip it.
			var httpErr *api.HTTPError
			if errors.As(err, &httpErr) {
				if strings.Contains(
					httpErr.Error(),
					"Dependabot alerts are disabled for this repository",
				) {
					return nil, nil
				}
			}

			return nil, fmt.Errorf(
				"get Dependabot alerts: %w",
				err,
			)
		}

		var page []Alert

		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf(
				"decode alerts for %s/%s: %w",
				owner,
				repo,
				err,
			)
		}

		alerts = append(alerts, page...)

		path = nextLink(headers.Get("Link"))
	}

	return alerts, nil
}

func alertURL(repo string, number int) string {
	return fmt.Sprintf(
		"https://github.com/%s/security/dependabot/%d",
		repo,
		number,
	)
}

func printAlert(repo string, alert Alert) {
	severity := strings.ToUpper(
		alert.SecurityVulnerability.Severity,
	)

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

	fmt.Printf(
		"  #%d [%s%s%s] %s\n",
		alert.Number,
		severityStyle,
		severityLabel,
		ansiReset,
		alert.Dependency.Package.Name,
	)

	if alert.SecurityAdvisory.Summary != "" {
		fmt.Printf(
			"      %s\n",
			alert.SecurityAdvisory.Summary,
		)
	}

	fmt.Printf(
		"      %s\n",
		alertURL(repo, alert.Number),
	)
}

func interrupted(ctx context.Context) bool {
	return ctx.Err() != nil
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
		fmt.Fprintf(
			os.Stderr,
			"error creating GitHub client: %v\n",
			err,
		)
		os.Exit(1)
	}

	s := newSpinner("Getting GitHub user")

	user, err := getUser(ctx, client)

	s.Stop()

	if err != nil {
		if interrupted(ctx) {
			fmt.Fprintln(os.Stderr, "Interrupted.")
			os.Exit(130)
		}

		fmt.Fprintf(
			os.Stderr,
			"error getting user: %v\n",
			err,
		)
		os.Exit(1)
	}

	s = newSpinner(
		fmt.Sprintf(
			"Getting repositories for %s",
			user.Login,
		),
	)

	repos, err := getRepositories(ctx, client)

	s.Stop()

	if err != nil {
		if interrupted(ctx) {
			fmt.Fprintln(os.Stderr, "Interrupted.")
			os.Exit(130)
		}

		fmt.Fprintf(
			os.Stderr,
			"error getting repositories: %v\n",
			err,
		)
		os.Exit(1)
	}

	for i, repo := range repos {
		if interrupted(ctx) {
			fmt.Fprintln(os.Stderr, "Interrupted.")
			os.Exit(130)
		}

		if repo.Archived {
			continue
		}

		message := fmt.Sprintf(
			"Checking %s (%d/%d)",
			repo.FullName,
			i+1,
			len(repos),
		)

		s := newSpinner(message)

		alerts, err := getAlerts(
			ctx,
			client,
			repo.Owner.Login,
			repo.Name,
		)

		s.Stop()

		if interrupted(ctx) {
			fmt.Fprintln(os.Stderr, "Interrupted.")
			os.Exit(130)
		}

		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"warning: %s: %v\n",
				repo.FullName,
				err,
			)
			continue
		}

		if len(alerts) == 0 {
			continue
		}

		fmt.Printf(
			"%s%s%s%s%s: %d open alerts\n",
			ansiBold,
			ansiBrightCyan,
			ansiUnderline,
			repo.FullName,
			ansiReset,
			len(alerts),
		)

		for _, alert := range alerts {
			printAlert(repo.FullName, alert)
		}

		fmt.Println()
	}

	fmt.Fprintln(os.Stderr, "Done.")
}
