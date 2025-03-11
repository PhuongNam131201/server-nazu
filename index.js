const express = require('express');
const app = express();
const cors = require('cors');
app.use(cors());

const PORT = 3001;
app.get('/auth/hello', (req, res) => {
    res.send('Hello World');
})
app.listen(PORT, (err) => {
	if (err) {
		console.log(err);
		return;
	}

	console.log(`Server starting at http://localhost:${PORT}`);
});