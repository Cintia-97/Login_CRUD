import Express from 'express';
// Initiate express
const app = Express();
app.use(Express.json());
// Setup “hello world” endpoint
const port = process.env.PORT || 3000;
app.get('*', (req, res) => res.send('Hello World!'));
// Start the express server on the relevant port
app.listen(port, () => {
    console.log(`server is running on ${port}`);
});
