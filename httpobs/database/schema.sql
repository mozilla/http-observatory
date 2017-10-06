CREATE TABLE IF NOT EXISTS sites (
  id                                  SERIAL PRIMARY KEY,
  domain                              VARCHAR(255) NOT NULL,
  creation_time                       TIMESTAMP NOT NULL,
  public_headers                      JSONB NULL,
  private_headers                     JSONB NULL,
  cookies                             JSONB NULL
);

CREATE TABLE IF NOT EXISTS expectations (
  id                                  SERIAL PRIMARY KEY,
  site_id                             INTEGER REFERENCES sites (id),
  test_name                           VARCHAR NOT NULL,
  expectation                         VARCHAR NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
  id                                  SERIAL PRIMARY KEY,
  site_id                             INTEGER REFERENCES sites (id) NOT NULL,
  state                               VARCHAR    NOT NULL,
  start_time                          TIMESTAMP  NOT NULL,
  end_time                            TIMESTAMP  NULL,
  algorithm_version                   SMALLINT   NOT NULL DEFAULT 1,
  tests_failed                        SMALLINT   NOT NULL DEFAULT 0,
  tests_passed                        SMALLINT   NOT NULL DEFAULT 0,
  tests_quantity                      SMALLINT   NOT NULL,
  grade                               VARCHAR(2) NULL,
  score                               SMALLINT   NULL,
  likelihood_indicator                VARCHAR    NULL,
  error                               VARCHAR    NULL,
  response_headers                    JSONB NULL,
  hidden                              BOOL       NOT NULL DEFAULT FALSE,
  status_code                         SMALLINT   NULL
);

CREATE TABLE IF NOT EXISTS tests (
  id                                  BIGSERIAL PRIMARY KEY,
  site_id                             INTEGER REFERENCES sites (id) NOT NULL,
  scan_id                             INTEGER REFERENCES scans (id) NOT NULL,
  name                                VARCHAR  NOT NULL,
  expectation                         VARCHAR  NOT NULL,
  result                              VARCHAR  NOT NULL,
  score_modifier                      SMALLINT NOT NULL,
  pass                                BOOL     NOT NULL,
  output                              JSONB    NOT NULL
);

CREATE INDEX sites_domain_idx            ON sites (domain);

CREATE INDEX scans_site_id_idx           ON scans (site_id);
CREATE INDEX scans_state_idx             ON scans (state);
CREATE INDEX scans_start_time_idx        ON scans (start_time);
CREATE INDEX scans_end_time_idx          ON scans (end_time);
CREATE INDEX scans_algorithm_version_idx ON scans (algorithm_version);
CREATE INDEX scans_grade_idx             ON scans (grade);
CREATE INDEX scans_score_idx             ON scans (score);
CREATE INDEX scans_hidden_idx            ON scans (hidden);

CREATE INDEX tests_scan_id_idx           ON tests (scan_id);
CREATE INDEX tests_name_idx              ON tests (name);
CREATE INDEX tests_result_idx            ON tests (result);
CREATE INDEX tests_pass_idx              ON tests (pass);

CREATE USER httpobsscanner;
GRANT SELECT on sites, scans, expectations, tests TO httpobsscanner;
GRANT UPDATE (domain) ON sites to httpobsscanner;  /* TODO: there's got to be a better way with SELECT ... FOR UPDATE */
GRANT UPDATE on scans TO httpobsscanner;
GRANT INSERT on tests TO httpobsscanner;
GRANT USAGE ON SEQUENCE tests_id_seq TO httpobsscanner;

CREATE USER httpobsapi;
GRANT SELECT ON expectations, scans, tests to httpobsapi;
GRANT SELECT (id, domain, creation_time, public_headers) ON sites TO httpobsapi;
GRANT INSERT ON sites, scans TO httpobsapi;
GRANT UPDATE (public_headers, private_headers, cookies) ON sites TO httpobsapi;
GRANT UPDATE ON scans TO httpobsapi;
GRANT USAGE ON SEQUENCE sites_id_seq TO httpobsapi;
GRANT USAGE ON SEQUENCE scans_id_seq TO httpobsapi;
GRANT USAGE ON SEQUENCE expectations_id_seq TO httpobsapi;

CREATE INDEX scans_site_id_finished_state_end_time_idx ON scans (site_id, state, end_time DESC) WHERE state = 'FINISHED';

CREATE MATERIALIZED VIEW latest_scans
  AS SELECT latest_scans.site_id, latest_scans.scan_id, s.domain, latest_scans.state,
    latest_scans.start_time, latest_scans.end_time, latest_scans.tests_failed, latest_scans.tests_passed,
    latest_scans.grade, latest_scans.score, latest_scans.error
  FROM sites s,
  LATERAL ( SELECT id AS scan_id, site_id, state, start_time, end_time, tests_failed, tests_passed, grade, score, error
            FROM scans WHERE site_id = s.id AND state = 'FINISHED' ORDER BY end_time DESC LIMIT 1 ) latest_scans;
CREATE UNIQUE INDEX latest_scans_scan_id_idx ON latest_scans (scan_id);
COMMENT ON MATERIALIZED VIEW latest_scans IS 'Most recently completed scan for a given website';
GRANT SELECT ON latest_scans TO httpobsapi;

CREATE MATERIALIZED VIEW latest_tests
  AS SELECT latest_scans.domain, tests.site_id, tests.scan_id, name, result, pass, output
  FROM tests
  INNER JOIN latest_scans
  ON (latest_scans.scan_id = tests.scan_id);
COMMENT ON MATERIALIZED VIEW latest_tests IS 'Test results from all the most recent scans';

CREATE MATERIALIZED VIEW grade_distribution
  AS SELECT grade, count(*)
    FROM latest_scans
    GROUP BY grade;
CREATE UNIQUE INDEX grade_distribution_grade_idx ON grade_distribution (grade);
COMMENT ON MATERIALIZED VIEW grade_distribution IS 'The grades and how many latest scans have that score';
GRANT SELECT ON grade_distribution TO httpobsapi;

CREATE MATERIALIZED VIEW grade_distribution_all_scans
  AS SELECT grade, count(*)
    FROM scans
    WHERE state = 'FINISHED'
    GROUP BY grade;
CREATE UNIQUE INDEX grade_distribution_all_scans_grade_idx ON grade_distribution_all_scans (grade);
COMMENT ON MATERIALIZED VIEW grade_distribution_all_scans IS 'The grades and how many scans have that score';
GRANT SELECT ON grade_distribution_all_scans TO httpobsapi;

/* Update to add cookies */
/*
ALTER TABLE sites ADD COLUMN cookies JSONB NULL;
GRANT UPDATE (cookies) ON sites TO httpobsapi;
 */

/* Update to add likelihood indicator */
/*
ALTER TABLE scans ADD COLUMN likelihood_indicator VARCHAR NULL;
*/

/* Update to frequently refresh latest_scans */
/*
GRANT SELECT ON latest_scans TO httpobsapi;
ALTER MATERIALIZED VIEW latest_scans OWNER TO httpobsscanner;
*/

/* Update to add earliest scans and a way to compare earliest and latest */
CREATE MATERIALIZED VIEW earliest_scans
  AS SELECT earliest_scans.site_id, earliest_scans.scan_id, s.domain, earliest_scans.state,
    earliest_scans.start_time, earliest_scans.end_time, earliest_scans.tests_failed, earliest_scans.tests_passed,
    earliest_scans.grade, earliest_scans.score, earliest_scans.error
  FROM sites s,
  LATERAL ( SELECT id AS scan_id, site_id, state, start_time, end_time, tests_failed, tests_passed, grade, score, error
            FROM scans WHERE site_id = s.id AND state = 'FINISHED' ORDER BY end_time ASC LIMIT 1 ) earliest_scans;
CREATE UNIQUE INDEX earliest_scans_scan_id_idx ON earliest_scans (scan_id);
COMMENT ON MATERIALIZED VIEW earliest_scans IS 'Oldest completed scan for a given website';
GRANT SELECT ON earliest_scans TO httpobsapi;

CREATE MATERIALIZED VIEW scan_score_difference_distribution
  AS SELECT earliest_scans.site_id, earliest_scans.domain, earliest_scans.score AS before, latest_scans.score AS after,
    (latest_scans.score - earliest_scans.score) AS difference
  FROM earliest_scans, latest_scans
  WHERE earliest_scans.site_id = latest_scans.site_id;
COMMENT ON MATERIALIZED VIEW scan_score_difference_distribution IS 'How much score has changed since first scan';
GRANT SELECT ON scan_score_difference_distribution TO httpobsapi;
CREATE UNIQUE INDEX scan_score_difference_distribution_site_id_idx ON scan_score_difference_distribution (site_id);
CREATE INDEX scan_score_difference_difference_distribution_idx ON scan_score_difference_distribution (difference);

CREATE MATERIALIZED VIEW scan_score_difference_distribution_summation
  AS SELECT DISTINCT difference, COUNT(difference) AS num_sites
  FROM scan_score_difference_distribution
  GROUP BY difference
  ORDER BY difference DESC;
CREATE UNIQUE INDEX scan_score_difference_distribution_summation_difference_idx ON scan_score_difference_distribution_summation (difference);
COMMENT ON MATERIALIZED VIEW scan_score_difference_distribution_summation IS 'How many sites have improved by how many points';
GRANT SELECT ON scan_score_difference_distribution_summation TO httpobsapi;

ALTER MATERIALIZED VIEW grade_distribution OWNER TO httpobsscanner;  /* so it can refresh */
ALTER MATERIALIZED VIEW grade_distribution_all_scans OWNER TO httpobsscanner;  /* so it can refresh */
ALTER MATERIALIZED VIEW latest_scans OWNER TO httpobsscanner;
ALTER MATERIALIZED VIEW earliest_scans OWNER TO httpobsscanner;
ALTER MATERIALIZED VIEW scan_score_difference_distribution OWNER TO httpobsscanner;
ALTER MATERIALIZED VIEW scan_score_difference_distribution_summation OWNER TO httpobsscanner;
ALTER MATERIALIZED VIEW latest_tests OWNER TO httpobsscanner;

/* Database updates to allow us to track changes in scoring over time */
/*
ALTER TABLE scans ADD COLUMN algorithm_version SMALLINT NOT NULL DEFAULT 1;
CREATE INDEX scans_algorithm_version_idx ON scans (algorithm_version);
*/