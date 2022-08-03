FROM python:3.10
COPY pingdom-operator.py requirements.txt /opt/pingdom-operator/
WORKDIR /opt/pingdom-operator
RUN pip install -r requirements.txt

CMD ["python", "/opt/pingdom-operator/pingdom-operator.py"]
