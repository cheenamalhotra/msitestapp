## Steps to run this example:

 Provide connection string in Environment variable "MSI_TEST_CONN_STRING" and run below commands when Docker is running:
```bash
docker image build . --tag msitokentestapp
docker run msitokentestapp
```
OR pull docker image and run with ENV variable "MSI_TEST_CONN_STRING" specified in DOCKERFILE:
```bash
docker pull cheenamalhotra/msitestapp:latest
```