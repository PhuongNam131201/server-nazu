const bcryp = require("bcrypt");
const UserModel = require("../src/models/userModel");
const asyncHandle = require("express-async-handler");
const jwt = require("jsonwebtoken");
const getJsonWebToken = async (email, id) => {
  //tao token cho user moi dang ky thanh cong de user do co the dang nhap vao he thong
  const payload = {
    //payload la noi dung cua token
    email, //email cua user moi dang ky thanh cong
    id,
  };
  const token = jwt.sign(payload, process.env.SECRET_KEY, {
    //tao token voi noi dung payload, SECRET_KEY la key bi mat
    expiresIn: "7d", //token co hieu luc trong 7 ngay ke tu luc tao ra token do
  }); // token giup xac thuc nguoi dung khi dang nhap vao he thong

  return token;
};
const register = asyncHandle(async (req, res) => {
  const { email, fullname, password } = req.body;

  const existingUser = await UserModel.findOne({ email });

  if (existingUser) {
    res.status(400); //400 la bad request
    throw new Error("Tai khoan da ton tai!!!"); //throw new Error la throw ra loi
  }

  const salt = await bcryp.genSalt(10);
  const hashedPassword = await bcryp.hash(password, salt); //ma hoa password

  const newUser = new UserModel({
    email,
    fullname: fullname ?? "",
    password: hashedPassword,
  });

  await newUser.save(); //save vao database

  res.status(200).json({
    // 200 la thanh cong, 201 la tao moi thanh cong
    message: "Register new user successfully",
    data: {
      email: newUser.email, //email cua user moi dang ky thanh cong
      id: newUser._id, //id cua user moi dang ky thanh cong
      accesstoken: await getJsonWebToken(email, newUser.id), //tao token cho user moi dang ky thanh cong
    },
  });
});
module.exports = {
  register,
};
