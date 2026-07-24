# sample-logs

`auth_sample.log` is a 15-line **illustrative excerpt** showing the raw log
format the parser expects:

It is not the benchmark dataset and is not used by the pipeline.
The evaluated dataset is 5,000 events generated deterministically by
`scripts/generate_synthetic_auth_logs.py` into `data/raw_auth_logs.log`.

Keep this file for format reference when reading `scripts/parse_auth_logs.py`.