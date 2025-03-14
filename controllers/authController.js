const bcryp = require("bcrypt");
const UserModel = require("../src/models/userModel");
const asyncHandle = require("express-async-handler");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
require("dotenv").config();
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
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  auth: {
    user: process.env.USERNAME_EMAIL,
    pass: process.env.PASSWORD_EMAIL,
  },
});
const handleSendMail = async (val) => {
  try {
    await transporter.sendMail(val);

    return "OK";
  } catch (error) {
    return error;
  }
};
const verification = asyncHandle(async (req, res) => {
  const { email } = req.body;

  const verificationCode = Math.round(100000 + Math.random() * 900000);

  try {
    const data = {
      from: `"Hỗ trợ ứng dụng" <${process.env.USERNAME_EMAIL}>`,
      to: email,
      subject: "Mã email xác minh",
      text: "Mã xác minh của bạn đã được gửi đến email",
      html: `<h1>${verificationCode}</h1>`,
    };

    await handleSendMail(data);

    res.status(200).json({
      message: "Send verification code successfully!!!",
      data: {
        code: verificationCode,
      },
    });
  } catch (error) {
    res.status(401);
    throw new Error("Không thể gửi mail");
  }
});
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
const login = asyncHandle(async (req, res) => {
  const { email, password } = req.body;

  const existingUser = await UserModel.findOne({ email });

  if (!existingUser) {
    res.status(403);
    throw new Error("Không tồn tại tài khoản!!!");
  }

  const isMatchPassword = await bcryp.compare(password, existingUser.password);

  if (!isMatchPassword) {
    res.status(401);
    throw new Error("Email hoặc mật khẩu không đúng!!!");
  }

  res.status(200).json({
    message: "Đăng nhập thành công",
    data: {
      id: existingUser.id,
      email: existingUser.email,
      accesstoken: await getJsonWebToken(email, existingUser.id),
      fcmTokens: existingUser.fcmTokens ?? [],
      photo: existingUser.photoUrl ?? "",
      name: existingUser.name ?? "",
    },
  });
});
module.exports = {
  register,
  login,
  verification,
};
