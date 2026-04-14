-- Purpose: Example DDL for a population / census table kept in the SAME database as Metabase (mosip_regprc connection).
-- Run once in your reporting database; load rows from official census or estimates.
-- Adjust columns to match your geography keys (must align with registration_list.location_code or your chosen join key).

CREATE TABLE IF NOT EXISTS public.population_reference (
  location_code VARCHAR(64) PRIMARY KEY,
  region_name VARCHAR(256),
  population_total BIGINT NOT NULL CHECK (population_total >= 0),
  reference_year SMALLINT,
  source VARCHAR(512),
  cr_dtimes TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE public.population_reference IS 'External population denominators for coverage %; keys must match registration_list.location_code (or change join in coverage SQL).';

-- Example seed (remove or replace):
-- INSERT INTO public.population_reference (location_code, region_name, population_total, reference_year, source)
-- VALUES ('DIST001', 'Example District', 500000, 2024, 'Census');
