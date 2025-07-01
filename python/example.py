from pulsar import Pulsar, HttpStatus, Request, Response

# Create Pulsar application
app = Pulsar()

# Logger middleware
def logger(req: Request, res: Response):
    print(f"{req.method} {req.path}")

def auth_middleware(req: Request, res: Response):
    if not req.get_header("Authorization"):
        res.send("Unauthorized", status=HttpStatus.UNAUTHORIZED)
        res.abort()
        return

# Global middleware.
# app.use(auth_middleware)

@app.GET("/")
def hello(req: Request, res: Response):
    res.set_header("Content-Type", "text/plain")
    content_type = res.get_header("Content-Type")

    res.send(f"Hello, World! Content-Type: {content_type}\n")

@app.GET("/greet/{name}")
def greet(req: Request, res: Response):
    name = req.get_path_param("name")
    res.send(f"Hello, {name}!")

@app.POST("/echo")
def echo(req: Request, res: Response):
    res.send(req.body)

@app.errorhandler
def handle_errors(err: Exception, req: Request, res: Response):
    res.send(f"Error occurred: {str(err)}", status=HttpStatus.INTERNAL_SERVER_ERROR)

# Serve static files
app.static("/static", ".")

# Start server
app.run(8080)

