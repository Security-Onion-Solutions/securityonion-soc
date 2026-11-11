-- Convert saved net_drops alarm thresholds from the 3.4.0 unit to drops per second.
--
-- 3.4.0 compared net_drops alarms against drop_in deltas per second multiplied by the
-- bytes-to-megabits factor 8 / 1e6, labelled "mbs". The value is now the unscaled drops
-- per second, so old_threshold * 8 / 1e6 = drops/s gives:
--   new_threshold = old_threshold / (8 / 1e6) = old_threshold * 125000
--
-- The alarm list is normally stored as a JSONB array, but a JSONB string holding the
-- array text is also accepted and written back as a string. numeric arithmetic keeps the
-- result exact and its text free of exponents; trailing fractional zeros are trimmed with
-- regexp_replace because trim_scale() needs PostgreSQL 13.
--
-- A row that can't be parsed or converted is left untouched with a warning, so bad saved
-- data can't stop SOC from starting.

DO $$
DECLARE
    rec       RECORD;
    alarms    JSONB;
    converted JSONB;
BEGIN
    FOR rec IN
        SELECT setting_id, node_id, value
        FROM settings
        WHERE setting_id = 'soc.config.server.modules.postgresmetrics.alarms'
          AND value IS NOT NULL
    LOOP
        BEGIN
            IF jsonb_typeof(rec.value) = 'string' THEN
                alarms := (rec.value #>> '{}')::jsonb;
            ELSE
                alarms := rec.value;
            END IF;

            IF jsonb_typeof(alarms) IS DISTINCT FROM 'array' THEN
                CONTINUE;
            END IF;

            SELECT jsonb_agg(
                       CASE
                           WHEN jsonb_typeof(elem) = 'object'
                            AND lower(btrim(elem->>'metric')) = 'net_drops'
                            AND btrim(elem->>'threshold') ~ '^[+-]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?$'
                           THEN jsonb_set(elem, '{threshold}', to_jsonb(
                               regexp_replace(
                                   regexp_replace(
                                       ((btrim(elem->>'threshold'))::numeric * 125000)::text,
                                       '(\.[0-9]*[1-9])0+$', '\1'),
                                   '\.0*$', '')))
                           ELSE elem
                       END
                       ORDER BY ord)
            INTO converted
            FROM jsonb_array_elements(alarms) WITH ORDINALITY AS t(elem, ord);

            IF converted IS NULL OR converted = alarms THEN
                CONTINUE;
            END IF;

            UPDATE settings
            SET value = CASE
                            WHEN jsonb_typeof(rec.value) = 'string' THEN to_jsonb(converted::text)
                            ELSE converted
                        END
            WHERE setting_id = rec.setting_id
              AND node_id = rec.node_id;
        EXCEPTION WHEN others THEN
            RAISE WARNING 'net_drops threshold migration skipped setting % on node %: %',
                rec.setting_id, rec.node_id, SQLERRM;
        END;
    END LOOP;
END
$$;
