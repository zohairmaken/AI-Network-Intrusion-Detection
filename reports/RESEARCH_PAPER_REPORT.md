# AI-Powered Network Intrusion Detection System: A Machine Learning Approach to Network Security

**Course Project Report: CS402 - Information Security**  
**Department of Computer Science**  

---

## Abstract
With the exponential increase in network traffic and the sophistication of cyber threats, traditional signature-based Intrusion Detection Systems (IDS) often fail to detect novel attack patterns. This paper proposes an AI-Powered Network Intrusion Detection System (NIDS) that utilizes Machine Learning (ML) algorithms for real-time traffic classification. The system architecture integrates raw packet capture via Scapy, statistical feature extraction, and high-performance classification using Random Forest, Decision Tree, and XGBoost models. Evaluation on synthetic and standardized datasets demonstrates a high detection accuracy exceeding 95% across multiple attack vectors, including Denial of Service (DoS), Port Scanning, and Brute Force attacks. The proposed solution is integrated into a professional-grade Security Operations Center (SOC) dashboard, providing real-time visualization and alerting for network administrators.

**Keywords:** Network Intrusion Detection, Machine Learning, Information Security, Random Forest, Scapy, Cyber Threat Intelligence.

---

## I. Introduction
Network security remains a paramount concern in the digital era, where the confidentiality, integrity, and availability of data are constantly under threat. Intrusion Detection Systems (IDS) serve as a secondary line of defense by monitoring network traffic for suspicious activities. However, the limitation of static rules in legacy systems has led to a paradigm shift towards anomaly-based detection using Artificial Intelligence. This research implements a modular NIDS that leverages ML to autonomously learn and identify malicious behaviors.

## II. Related Work
Contemporary research in NIDS has evolved from simple heuristic filters to complex deep learning architectures. Standard datasets such as NSL-KDD and CICIDS2017 have been instrumental in benchmarking ML models. Previous studies indicate that ensemble methods, particularly Random Forests, provide an optimal balance between computational efficiency and detection accuracy for tabular network data. This project builds upon these findings by implementing a real-time, end-to-end monitoring pipeline.

## III. Proposed Methodology
The proposed system follows a structured pipeline consisting of four major phases:

### A. Packet Acquisition and Preprocessing
The system utilizes the Scapy library to sniff raw IP packets in a background daemon thread. For each network flow, 18 behavioral features are extracted, including:
- **Temporal Features:** Duration, Inter-arrival time (IAT).
- **Protocol Features:** Protocol type, Destination port, TCP flags.
- **Statistical Features:** Packet count, Byte count, Flow rate.

### B. Machine Learning Framework
The detection engine supports three primary classifiers:
1. **Random Forest (RF):** An ensemble of 200 decision trees using bagging to reduce variance.
2. **Decision Tree (DT):** A baseline CART-based classifier for model interpretability.
3. **XGBoost:** A gradient-boosted framework optimized for speed and performance.

### C. Threat Severity Analysis
Beyond classification, the system implements a heuristic scoring engine that calculates a **Risk Score (0-1.0)** and assigns a severity level (**LOW, MEDIUM, HIGH, CRITICAL**) based on model confidence and the target port's sensitivity.

## IV. System Architecture and Implementation
The implementation is highly modular, separating the logic into four distinct layers:
1. **Data Layer:** Handles dataset ingestion and synthetic data generation.
2. **Core Engine:** Manages sniffing, extraction, and ML inference.
3. **Application Layer:** A Streamlit-based UI for real-time visualization.
4. **Logging Layer:** Persistence of attack records for forensic analysis.

## V. Results and Analysis
The models were evaluated using Accuracy, Precision, Recall, and F1-Score.

| Model | Accuracy | Precision | Recall | F1-Score |
|-------|----------|-----------|--------|----------|
| Random Forest | 97.2% | 97.0% | 97.2% | 97.1% |
| XGBoost | 96.5% | 96.3% | 96.5% | 96.4% |
| Decision Tree | 93.4% | 93.1% | 93.4% | 93.2% |

Experimental results show that the **Random Forest** model performs exceptionally well in distinguishing between high-rate DoS attacks and normal background traffic, with minimal false-positive rates.

## VI. Conclusion and Future Work
This project demonstrates the efficacy of Machine Learning in enhancing information security. By combining real-time packet analysis with predictive modeling, the system provides a robust defense mechanism against common network threats. Future work will focus on integrating Recurrent Neural Networks (RNNs) for sequential analysis of packet payloads and implementing automated firewall rule orchestration for active response.

---

## References
1. Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. ICISSP.
2. Tavallaee, M., Bagheri, E., Lu, W., & Ghorbani, A. A. (2009). *A detailed analysis of the KDD CUP 99 data set*. IEEE Symposium on Computational Intelligence for Security and Defense Applications.
3. Pedregosa, F., et al. (2011). *Scikit-learn: Machine Learning in Python*. Journal of Machine Learning Research.
4. Biondi, P., et al. (2024). *Scapy: Interactive packet manipulation tool*.
