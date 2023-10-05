FROM python:3.12
COPY library /opt/pingdom-operator/library
COPY pingdom-operator.py requirements.txt /opt/pingdom-operator/
WORKDIR /opt/pingdom-operator
RUN pip install -r requirements.txt

CMD ["python3", "-u", "/opt/pingdom-operator/pingdom-operator.py"]
