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
  tests_completed                     SMALLINT   NOT NULL DEFAULT 0,
  tests_failed                        SMALLINT   NOT NULL DEFAULT 0,
  tests_passed                        SMALLINT   NOT NULL DEFAULT 0,
  tests_quantity                      SMALLINT   NOT NULL,
  error                               VARCHAR    NULL,
  grade                               VARCHAR(2) NULL,
  grade_reasons                       JSONB      NULL
);

CREATE TABLE IF NOT EXISTS tests (
  id                                  BIGSERIAL PRIMARY KEY,
  site_id                             INTEGER REFERENCES sites (id),
  scan_id                             INTEGER REFERENCES scans (id),
  name                                VARCHAR NOT NULL,
  expectation                         VARCHAR NOT NULL,
  result                              VARCHAR NOT NULL,
  pass                                BOOL    NOT NULL,
  output                              JSONB   NOT NULL
);

CREATE INDEX sites_domain_idx ON sites (domain);
CREATE INDEX tests_name_idx   ON tests (name);

CREATE ROLE httpobsscanner;
GRANT SELECT, INSERT ON sites, expectations, scans, tests TO httpobsscanner;
GRANT UPDATE on sites, expectations, scans TO httpobsscanner;

CREATE ROLE httpobsapi;
GRANT SELECT ON expectations, scans, tests to httpobsapi;
GRANT SELECT (id, domain, public_headers) ON sites TO httpobsapi;
GRANT INSERT, UPDATE ON sites, expectations to httpobsapi;
GRANT INSERT, UPDATE (private_headers) ON sites to httpobsapi;

SET MAX_CONNECTIONS TO 256;
