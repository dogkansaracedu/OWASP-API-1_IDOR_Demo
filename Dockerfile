FROM python:latest

COPY ./requirements.txt /app/requirements.txt
COPY app.py ./app.py

WORKDIR /app

RUN pip install -r requirements.txt

COPY . /app

EXPOSE 5000
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0"]  
