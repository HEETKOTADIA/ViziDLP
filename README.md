# ViziDLP

ViziDLP is an AI powered Data Loss Prevention system designed to detect and protect sensitive information in real time. The project focuses on monitoring on screen content, identifying personally identifiable information, and preventing accidental data exposure during screenshots, screen recording, or screen sharing.

The system combines OCR, computer vision, and intelligent monitoring techniques to identify sensitive content such as Aadhaar numbers, PAN cards, phone numbers, email addresses, and other confidential information. Once detected, the sensitive regions can be blurred, blocked, or protected automatically.

## Features

* Real time OCR based text detection
* Detection of sensitive information and PII
* Aadhaar card detection
* PAN card detection
* Phone number and email detection
* Automatic blur protection during screenshots
* Screen recording protection
* Region based content masking
* Real time monitoring of active windows
* Lightweight desktop monitoring system
* AI assisted sensitive data identification

## Technologies Used

* Python
* OpenCV
* OCR Engine
* YOLO based object detection
* Machine Learning
* Computer Vision

## Project Objective

The main objective of ViziDLP is to reduce accidental data leakage by protecting sensitive information displayed on screen. The system is designed for educational, research, and cybersecurity related use cases where privacy and data protection are important.

## How It Works

1. The system continuously monitors screen activity.
2. OCR extracts visible text from the screen.
3. AI models analyze the detected text and visual regions.
4. Sensitive information is identified in real time.
5. The detected regions are blurred or blocked automatically.

## Installation

Clone the repository:

```bash
git clone https://github.com/your-username/ViziDLP.git
```

Move into the project directory:

```bash
cd ViziDLP
```

Install required dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python main.py
```

## Use Cases

* Preventing accidental data exposure
* Protecting confidential documents
* Securing screenshots and recordings
* Cybersecurity research
* Privacy focused desktop monitoring
* Enterprise DLP experimentation

## Future Improvements

* Cloud based monitoring dashboard
* Advanced AI classification
* Browser extension support
* Multi monitor support
* User behavior analytics
* Enterprise level policy management

## Disclaimer

This project is developed for educational and research purposes only. The system should be used responsibly and ethically.
