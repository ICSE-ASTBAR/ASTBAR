# ASTBAR
ASTBAR - Utilized for benign software detection in webshell detection tasks, effectively reducing the False Positive Rate (FPR) of AV engines.


## Dataset

We meticulously curated a large-scale dataset comprising well-annotated samples of malicious and benign software. The benign software primarily originated from popular Content Management Systems (CMS), such as WordPress, ThinkPHP, and Symfony, which were scraped from GitHub. After a rigorous deduplication process, a total of 132,333 benign samples were obtained. On the other hand, the malicious samples were predominantly sourced from a cloud computing company, representing real-world industrial samples. This malicious subset encompassed various categories, including highly adversarial samples, surgical malware specimens, and different malware families. After the removal of duplicates, a total of 50,063 malicious samples were included in the dataset. 


**Due to the large size of the dataset, we only provide example AST files of the relevant samples in the repository. Please send us an email to obtain the complete dataset.**





## Usage

0. Install dependencies
   
Ensure you are using Python 3.8 or later, and install the required dependencies:


```
pip install tqdm redis
```




1. Generating the Model File with an Existing Dataset
First, configure the dataset directory and specify the name for the generated model:


```
src_path = '../dataset/benign'
model_name = 'model/sys2_1.pkl'
```

Then, generate the model by running:


```
python3 gen_ast.py
```

2. Directory Configuration for Detection

Next, configure the model path and the directory that needs to be scanned for detection:


```
target_path = '../dataset/malware'
file_name = 'model/sys2_1.pkl'
```

Then, execute the detection script:


```
python3 predict_base.py
```

3. Checking Output Information

After running the detection script, review the output to see the MD5 hashes of the detected benign files:


```
Loaded Set: 474383
Started benign detect!
benign file: ../icse/benign_test/1294f134dc5620c1c1659e96ee5b9c81
benign file: ../icse/benign_test/193af70650574467512465b4ae702a04
benign file: ../icse/benign_test/13a9bd03e4477831670698bdb10f1b99
benign file: ../icse/benign_test/8f89afbdc1f186f0bc33b4c807c1aed4
benign file: ../icse/benign_test/97d50eaaeb2288bae1915ca7cb087049
benign file: ../icse/benign_test/184b8b189db9a92cd50d9613df29503d
benign file: ../icse/benign_test/c9c510756f84bd66c3490faec67de5da
benign file: ../icse/benign_test/72bfdc7fc947561cee984007a3ce3375
...
benign file: ../icse/benign_test/b65b65cd2a165340fcc2ca7da5398e22
benign file: ../icse/benign_test/b9e77b06f611192b1f944d173e0cf59b
benign file: ../icse/benign_test/fea19a076f65458f2aefdae2498bd9b8
52101 103416 0.5038001856579253
```

By following these instructions, you will be able to generate the model files and perform detection using the provided datasets effectively.


## Disclaimer
This project is the code implementation of the “Distilling Benign Knowledge with Fine-Grained AST Fragments for Precise Real-World Web Shell Detection” paper. If you use this project, please cite our paper.



