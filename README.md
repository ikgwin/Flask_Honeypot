This flask honeypot was made to capture traffic for an organisation (with all sensitive data removed). It formats the output to JSON, CSV and regular .Log files.
This allowed log ingestion to a SEIM to perform queries on and block IPs from entering genuine systems, further improving the orgs security posture.
This also allowed for statistical modelling of the most frequent kinds of attacks on their systems.

The honeypot mimics an Outlook sign in page, where regular events that were captured included file inclusions, SQL injections, input validation attacks, and more.

