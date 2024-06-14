# ASTBAR
ASTBAR - Utilized for benign software detection in webshell detection tasks, effectively reducing the False Positive Rate (FPR) of AV engines.


## Dataset

We meticulously curated a large-scale dataset comprising well-annotated samples of malicious and benign software. The benign software primarily originated from popular Content Management Systems (CMS), such as WordPress, ThinkPHP, and Symfony, which were scraped from GitHub. After a rigorous deduplication process, a total of 132,333 benign samples were obtained. On the other hand, the malicious samples were predominantly sourced from a cloud computing company, representing real-world industrial samples. This malicious subset encompassed various categories, including highly adversarial samples, surgical malware specimens, and different malware families. After the removal of duplicates, a total of 50,063 malicious samples were included in the dataset. 





## Usage

1. Generating the Model File with an Existing Dataset
Please use the existing dataset to generate the model file for benign knowledge first. Configure the dataset directory and the name of the generated model accordingly.


```
src_path = '../dataset/benign'
model_name = 'model/sys2_1.pkl'
```

Then run the gen_ast.py

```
python3 gen_ast.py
```

2. Directory Configuration for Detection

Next, configure the model path and directory that needs to be scanned for detection. Then, execute the predict_base.py file.

```
target_path = '../dataset/malware'
file_name = 'model/sys2_1.pkl'
```

Then run the predict_base.py

```
python3 predict_base.py
```

3. Checking Output Information


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
