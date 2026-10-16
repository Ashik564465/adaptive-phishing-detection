FROM public.ecr.aws/lambda/python:3.12

COPY requirements.txt ${LAMBDA_TASK_ROOT}/

RUN pip install \
    --no-cache-dir \
    -r ${LAMBDA_TASK_ROOT}/requirements.txt \
    --target ${LAMBDA_TASK_ROOT}

COPY api ${LAMBDA_TASK_ROOT}/api
COPY src ${LAMBDA_TASK_ROOT}/src
COPY models ${LAMBDA_TASK_ROOT}/models
COPY data/threat_intelligence ${LAMBDA_TASK_ROOT}/data/threat_intelligence

CMD ["api.lambda_handler.lambda_handler"]