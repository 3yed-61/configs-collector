
# configs-collector

## About
A Python-based tool designed to automatically collect, classify, and organize configuration files using customizable classification logic.

## Features
- Automatic scanning and ingestion of configuration files.
- Classification module (`sub_classifier.py`) for applying custom rules.
- Structured output folders for organized processing.
- Easy to extend with additional classifiers or data types.

## Requirements
- Python 3.8+
- Install dependencies:
  ```bash
  pip install -r requirements.txt
  ```

## Installation
Clone the repository:
```bash
git clone https://github.com/3yed-61/configs-collector.git
cd configs-collector
```

(Optional) Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate    # Linux/macOS
venv\Scripts\activate     # Windows
```

Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage
Run the classifier script:
```bash
python sub_classifier.py --input path/to/configs --output classified_output/
```

Arguments:
- `--input` : Path to config files or directory
- `--output`: Destination folder for classified configs

## Example
```bash
python sub_classifier.py --input raw-configs/ --output classified_output/
```

## Development
1. Fork the repository
2. Create a feature branch:
   ```bash
   git checkout -b feature/my-new-classifier
   ```
3. Commit changes and submit a Pull Request with a clear explanation.

## Contributing
Contributions are welcome.  
Please ensure:
- Clear explanation of changes
- Tests (if applicable)
- Clean and readable code

## License
This project is licensed under the Apache License 2.0.

## Contact
Open an Issue in the repository for questions, bugs, or suggestions.
