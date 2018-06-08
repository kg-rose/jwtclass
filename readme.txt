jwt类，用于生产jwt和解密jwt

用法
   $jwt = new Jwt();
   $jwttoken = new JwtToken($jwt);
   //生产
   $token = $jwttoken->setToken();
   //解密
   $check = json_decode($jwttoken->checkToken($token));
