# fmc-ansible

**fmc_object** role will create network, host, or range objects within FMC on the global domain. The speed at which is searches the global domain object's is dependent on how many objects there are as it has to search all objects every time. This role contains a custom module we wrote.

Requirements: urllib3, requests, json, time, sys, re
Use pip to install 

To Do:
fmc_accessrule
fmc_prefilter