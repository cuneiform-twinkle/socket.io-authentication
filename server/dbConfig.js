const mongoose = require('mongoose');

const dbConfig = async (DB_URL, DB_NAME) => {
  try {
    const options= { useNewUrlParser: true, useUnifiedTopology: true };
    const localURL= DB_URL + DB_NAME;
    const URI= localURL;
    await mongoose
      .connect(URI, options)
      .then(() => console.log("MongoDB Connected Successfully"));
  } catch (error) {
    console.log(error);
  }
};

module.exports = dbConfig;