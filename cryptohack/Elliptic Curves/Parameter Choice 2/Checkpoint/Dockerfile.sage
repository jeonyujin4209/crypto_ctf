FROM sagemath/sagemath:latest
RUN sage --pip install pycryptodome pwntools
