@app.route('/raw')
def index():
    param = request.args.get('param', 'not set')
    result = db.engine.execute(param)
    print(User.query.all(), file=sys.stderr)
    return 'Result is displayed in console'