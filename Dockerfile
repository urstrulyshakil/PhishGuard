FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

EXPOSE 8501

# Retrain if dataset changed, then start Streamlit
CMD python train_model.py && streamlit run app/main.py --server.port=8501 --server.address=0.0.0.0