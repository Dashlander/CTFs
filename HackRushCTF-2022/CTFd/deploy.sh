exec gunicorn 'CTFd:create_app()' \
    --bind '0.0.0.0:5000' \
    --workers 1\
    --worker-class "gevent" \

