@load ../../scripts

# Omit body samples in deterministic regression output.
redef PHP2SHELL::notice_body_sample_bytes = 0;
