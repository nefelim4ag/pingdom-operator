FROM python:3.11
COPY pingdom-operator.py requirement.txt /opt/pingdom-operator/
WORKDIR /opt/pingdom-operator
RUN pip install -r requirement.txt

CMD ["python", "/opt/pingdom-operator/pingdom-operator.py"]
