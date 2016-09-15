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
  tests_failed                        SMALLINT   NOT NULL DEFAULT 0,
  tests_passed                        SMALLINT   NOT NULL DEFAULT 0,
  tests_quantity                      SMALLINT   NOT NULL,
  grade                               VARCHAR(2) NULL,
  score                               SMALLINT   NULL,
  error                               VARCHAR    NULL,
  response_headers                    JSONB NULL,
  hidden                              BOOL       NOT NULL DEFAULT FALSE
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

CREATE INDEX sites_domain_idx     ON sites (domain);

CREATE INDEX scans_site_id_idx    ON scans (site_id);
CREATE INDEX scans_state_idx      ON scans (state);
CREATE INDEX scans_start_time_idx ON scans (start_time);
CREATE INDEX scans_end_time_idx   ON scans (end_time);
CREATE INDEX scans_grade_idx      ON scans (grade);
CREATE INDEX scans_score_idx      ON scans (score);
CREATE INDEX scans_hidden_idx     ON scans (hidden);

CREATE INDEX tests_scan_id_idx    ON tests (scan_id);
CREATE INDEX tests_name_idx       ON tests (name);
CREATE INDEX tests_result_idx     ON tests (result);
CREATE INDEX tests_pass_idx       ON tests (pass);

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
COMMENT ON MATERIALIZED VIEW latest_scans IS 'Most recently completed scan for a given website';

CREATE MATERIALIZED VIEW latest_tests
  AS SELECT latest_scans.domain, tests.site_id, tests.scan_id, name, result, pass, output
  FROM tests
  INNER JOIN latest_scans
  ON (latest_scans.scan_id = tests.scan_id);
COMMENT ON MATERIALIZED VIEW latest_tests IS 'Test results from all the most recent scans';

CREATE MATERIALIZED VIEW grade_distribution
  AS SELECT grade, count(*)
    FROM scans
    WHERE state = 'FINISHED'
    GROUP BY grade;
COMMENT ON MATERIALIZED VIEW grade_distribution IS 'The grades and how many scans have that score';
GRANT SELECT ON grade_distribution TO httpobsapi;
ALTER MATERIALIZED VIEW grade_distribution OWNER TO httpobsscanner;  /* so it can refresh */

/* Update to add cookies */
/*
ALTER TABLE sites ADD COLUMN cookies JSONB NULL;
GRANT UPDATE (cookies) ON sites TO httpobsapi;
 */