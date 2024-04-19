#### The following enhancements have been made to the MISP Connector in version 2.0.2:
- The indicator enrichment playbook File Hash / Domain / IP / URL > MISP > Enrichment includes enriching file hashes, domains, IPs and URLs via MISP. Optionally, it retrieves the indicator reputation and calculates the reputation summary from the MISP.
- Added the following new operations and playbooks: 
    - Get Users
    - Get Organization

- The action `Add Event` has following new parameters:
  - Extends Events 
  - Additional Attributes
- The action `Add Tag` has a new parameter `Color` 
