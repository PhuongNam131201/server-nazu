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
      from: `"Hỗ trợ Ứng Dụng" <${process.env.USERNAME_EMAIL}>`,
      to: email,
      subject: "Xác minh tài khoản - Mã xác nhận của bạn",
      text: "Bạn đã yêu cầu mã xác minh để đăng ký hoặc đăng nhập vào ứng dụng. Vui lòng sử dụng mã dưới đây để hoàn tất quá trình xác thực:",
      html: `
        <p>Xin chào,</p>
        <p>Bạn đã yêu cầu mã xác minh để đăng ký hoặc đăng nhập vào ứng dụng. Vui lòng sử dụng mã dưới đây để hoàn tất quá trình xác thực:</p>
        <h2 style="color: #2d89ff; font-size: 24px;">${verificationCode}</h2>
        <p>Lưu ý: Mã xác minh có hiệu lực trong 2 phút. Không chia sẻ mã này với bất kỳ ai.</p>
        <p>Nếu bạn không yêu cầu mã này, vui lòng bỏ qua email này.</p>
        <p>Trân trọng,</p>
        <p><strong>Đội ngũ hỗ trợ Ứng Dụng</strong></p>
      `,
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
const forgotPassword = asyncHandle(async (req, res) => {
  const { email } = req.body;

  const randomPassword = Math.round(100000 + Math.random() * 99000);

  const data = {
    from: `"NAZU Support" <${process.env.USERNAME_EMAIL}>`,
    to: email,
    subject: "Khôi phục mật khẩu tài khoản NAZU",
    text: `Xin chào ${email},\n\nChúng tôi đã nhận được yêu cầu đặt lại mật khẩu cho tài khoản của bạn.\nMật khẩu mới của bạn là: ${randomPassword}\n\nVui lòng đăng nhập và thay đổi mật khẩu ngay để đảm bảo an toàn.\nNếu bạn không yêu cầu điều này, hãy bỏ qua email này hoặc liên hệ với chúng tôi.`,
    html: `
        <p>Xin chào <strong>${email}</strong>,</p>
        <p>Chúng tôi đã nhận được yêu cầu đặt lại mật khẩu cho tài khoản của bạn trên ứng dụng <strong>NAZU</strong>.</p>
        <p>Dưới đây là mật khẩu mới của bạn:</p>
        <h2 style="color: #2d89ff; font-size: 24px;">${randomPassword}</h2>
        <p><strong>Lưu ý:</strong> Vì lý do bảo mật, vui lòng đăng nhập và thay đổi mật khẩu ngay sau khi nhận được email này.</p>
        <p>Nếu bạn không yêu cầu đặt lại mật khẩu, vui lòng bỏ qua email này hoặc liên hệ với chúng tôi để được hỗ trợ.</p>
        <p>Trân trọng,</p>
        <p><strong>Đội ngũ hỗ trợ NAZU</strong></p>
    `,
  };

  const user = await UserModel.findOne({ email });
  if (user) {
    const salt = await bcryp.genSalt(10);
    const hashedPassword = await bcryp.hash(`${randomPassword}`, salt);

    await UserModel.findByIdAndUpdate(user._id, {
      password: hashedPassword,
      isChangePassword: true,
    })
      .then(() => {
        console.log("Done");
      })
      .catch((error) => console.log(error));

    await handleSendMail(data)
      .then(() => {
        res.status(200).json({
          message: "Send email new password successfully!!!",
          data: [],
        });
      })
      .catch((error) => {
        res.status(401);
        throw new Error("Can not send email");
      });
  } else {
    res.status(401);
    throw new Error("User not found!!!");
  }
});

module.exports = {
  register,
  login,
  verification,
  forgotPassword,
};
