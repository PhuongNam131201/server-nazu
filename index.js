const express = require('express');
const app = express();
const cors = require('cors');
const authRouter = require('./routers/authRouter');
app.use(cors());
app.use(express.json());
const PORT = 3001;
app.use('/auth',authRouter);
app.listen(PORT, (err) => {
	if (err) {
		console.log(err);
		return;
	}

	console.log(`Server starting at http://localhost:${PORT}`);
});