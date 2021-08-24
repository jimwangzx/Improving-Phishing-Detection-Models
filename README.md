# Stacked model README


## Requirements
Test with Linux machine.

From the main Phishing-Detection-Automated-Testing directory containing the requirements file, run   
`pip install -r requirements.txt`


## How to run

### Manually collecting training data
Our domain-based model uses text files to train, whereas Off-the-Hook's content-based model uses JSON files. In order to use the same domains to train both, we follow the steps below.

#### Initial text file data collection
To extract domains from Alexa, run   
`python3 get_alexa_domains.py [number of benign domains]`   
  [number of benign domains]: int representing the number of domains to extract.  

To extract domains from Phishtank, run   
`python3 get_phishing_domains.py [number of phishing domains]`   
   [number of phishing domains]: int representing the number of domains to extract.   

To verify those Phishtank domains with VirusTotal, run   
`python3 check_domain_with_vt.py`   

#### JSON file data collection and final text file data collection
To obtain a folder containing JSON files captured from the domain text files, run   
`python3 generate_JSON.py [path to training text file]`   
  [path to training text file]: str representing the path to the text file containing domains with which to train the model.   

In our case, we run it twice, once for each class of domain, benign and phishing.   
Run   
`python3 generate_JSON.py /var/tmp/phishing/benign_domains.txt`   
Manually rename the websites directory created in the Phishing-Detection-Automated-Testing project to "benign_train".   
Manually rename the after_JSON_filtering.txt text file created in the Phishing-Detection-Automated-Testing project to "benign_train.txt". Move the file from the current directory to the /var/tmp/phishing directory which contains the other domain text files.    

Run   
`python3 generate_JSON.py /var/tmp/phishing/phishing_domains_VT.txt`   
Manually rename the websites directory created in the Phishing-Detection-Automated-Testing project to "phishing_train".   
Manually rename the after_JSON_filtering.txt text file created in the Phishing-Detection-Automated-Testing project to "phishing_train.txt". Move the file from the current directory to the /var/tmp/phishing directory which contains the other domain text files.    


### Training our domain-based model
To train our model, run   
`python3 train.py`   


### Training Off-the-Hook's content-based model
We must first generate pkl files by running   
`python3 generate_JSON.py [websites_dir] [prefix] [target]`   
  [websites_dir] parameter: str representing the path to the directory containing the JSON files.   
  [prefix]: str representing the name to be assigned to the pickle file generated.   
  [target]: int representing the label of the domains from which features were extracted (benign: 0, phishing: 1).   

In our case, we run it twice, once for each class of domain, benign and phishing.   
Run  
`python3 generate_pkl.py phishing_train phishing_train 1`  
Run  
`python3 generate_pkl.py benign_train benign_train 0`  

To train Off-the-Hook's model, run  
`python3 build_model.py 0 benign_train_fvm.pkl phishing_train_fvm.pkl model`
For more information on the build_model script, consult Off-the-Hook-README.txt.

### Testing the stacked model
To test the stacked model, run   
`python3 automate_testing.py [test case size]`   
  [test case size]: int representing both the number of benign domains and phishing domains to test the model with. The total number of domains tested is 2*[test case size].

## Desired result
The final output should be a simple table with the number of FP, FN, TP and TN domains, and the accuracy of the stacked model.
