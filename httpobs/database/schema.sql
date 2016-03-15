CREATE TABLE IF NOT EXISTS sites (
  id                                  SERIAL PRIMARY KEY,
  domain                              VARCHAR(255) NOT NULL,
  creation_time                       TIMESTAMP NOT NULL,
  public_headers                      JSONB NULL,
  private_headers                     JSONB NULL
);

CREATE TABLE IF NOT EXISTS expectations (
  id                                  SERIAL PRIMARY KEY,
  site_id                             INTEGER REFERENCES sites (id),
  test_name                           VARCHAR NOT NULL,
  expectation                         VARCHAR NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
  id                                  SERIAL PRIMARY KEY,
  site_id                             INTEGER REFERENCES sites (id),
  state                               VARCHAR    NOT NULL,
  start_time                          TIMESTAMP  NOT NULL,
  end_time                            TIMESTAMP  NULL,
  tests_failed                        SMALLINT   NOT NULL DEFAULT 0,
  tests_passed                        SMALLINT   NOT NULL DEFAULT 0,
  tests_quantity                      SMALLINT   NOT NULL,
  grade                               VARCHAR(2) NULL,
  score                               SMALLINT   NULL,
  error                               VARCHAR    NULL,
  hidden                              BOOL       NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS tests (
  id                                  BIGSERIAL PRIMARY KEY,
  site_id                             INTEGER REFERENCES sites (id),
  scan_id                             INTEGER REFERENCES scans (id),
  name                                VARCHAR  NOT NULL,
  expectation                         VARCHAR  NOT NULL,
  result                              VARCHAR  NOT NULL,
  score_modifier                      SMALLINT NOT NULL,
  pass                                BOOL     NOT NULL,
  output                              JSONB    NOT NULL
);

CREATE INDEX sites_domain_idx     ON sites (domain);

CREATE INDEX scans_state_idx      ON scans (state);
CREATE INDEX scans_start_time_idx ON scans (start_time);
CREATE INDEX scans_end_time_idx   ON scans (end_time);
CREATE INDEX scans_grade_idx      ON scans (grade);
CREATE INDEX scans_score_idx      ON scans (score);
CREATE INDEX scans_hidden_idx     ON scans (hidden);

CREATE INDEX tests_name_idx       ON tests (name);
CREATE INDEX tests_result_idx     ON tests (result);
CREATE INDEX tests_pass_idx       ON tests (pass);

CREATE USER httpobsscanner;
GRANT SELECT, INSERT ON sites, expectations, scans, tests TO httpobsscanner;
GRANT UPDATE on sites, expectations, scans TO httpobsscanner;
GRANT USAGE ON SEQUENCE expectations_id_seq TO httpobsscanner;
GRANT USAGE ON SEQUENCE scans_id_seq TO httpobsscanner;
GRANT USAGE ON SEQUENCE tests_id_seq TO httpobsscanner;

CREATE USER httpobsapi;
GRANT SELECT ON expectations, scans, tests to httpobsapi;
GRANT SELECT (id, domain, creation_time, public_headers) ON sites TO httpobsapi;
GRANT INSERT ON sites to httpobsapi;
GRANT UPDATE (public_headers, private_headers) ON sites to httpobsapi;
GRANT USAGE ON SEQUENCE sites_id_seq TO httpobsapi;

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
