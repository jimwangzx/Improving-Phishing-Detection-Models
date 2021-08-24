## Stacked model README

### Requirements
Test with Linux machine.

From the Phishing-Detection-Automated-Testing directory, run   
`pip install -r requirements.txt`

### How to run
From the Phishing-Detection-Automated-Testing directory, run
`python3 automate_testing.py [test case size]`   
The [test case size] is an int representing both the number of benign domains and phishing domains you would like to test the model with. The total number of domains tested is 2*[test case size].

### Desired result
The final output should be a simple table with the number of FP, FN, TP and TN domains, and the accuracy of the stacked model.
