Compile instructions within docker:
docker build -t pintool .
docker run --rm -v $(pwd):/code -it pintool /bin/bash
cd /code
make clean && make
