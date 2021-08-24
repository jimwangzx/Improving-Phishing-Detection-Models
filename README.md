## Stacked model README

### Requirements
Test with Linux machine.

From the main Phishing-Detection-Automated-Testing directory containing the requirements file, run   
`pip install -r requirements.txt`

### How to run
#### Collecting training data

To extract domains from Alexa, run   
`python3 get_alexa_domains.py [number of benign domains]`   
The [number of benign domains] parameter is an int representing the number of domains to extract.  

To extract domains from Phishtank, run   
`python3 get_phishing_domains.py [number of phishing domains]`   
The [number of phishing domains] parameter is an int representing the number of domains to extract.   

To verify those Phishtank domains with VirusTotal, run   
`python3 check_domain_with_vt.py`   


#### Manually training Off-the-Hook's content-based model   
To obtain a folder containing JSON files captured from the domain text files, run   
`python3 generate_JSON.py [path to training text file]`   
The parameter [path to training text file] is a string representing the path to the text file containing domains with which to train the model.   

In our case, run it twice, once for each class of domain, benign and phishing.   
Run   
`python3 generate_JSON.py /var/tmp/phishing/benign_domains.txt`   
Then, manually rename the resulting after_JSON_filtering.txt to "phishing_train.txt". Move the file from the current Phishing-Detection-Automated-Testing directory to the /var/tmp/phishing directory which contains the other domain text files.

Run   
`python3 generate_JSON.py /var/tmp/phishing/phishing_domains_VT.txt`   
Then, manually rename the resulting after_JSON_filtering.txt to "benign_train.txt". Move the file from the current Phishing-Detection-Automated-Testing directory to the /var/tmp/phishing directory which contains the other domain text files.


Manually rename the websites directory created in the Phishing-Detection-Automated-Testing project to "phishing_train"

#### Training our domain-based model
To train our model using gradient boosting, run   
`python3 train.py`   

To test the stacked model, run   
`python3 automate_testing.py [test case size]`   
The [test case size] parameter is an int representing both the number of benign domains and phishing domains to test the model with. The total number of domains tested is 2*[test case size].

### Desired result
The final output should be a simple table with the number of FP, FN, TP and TN domains, and the accuracy of the stacked model.
