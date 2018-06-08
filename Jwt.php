<?php
namespace app\core\helper;

use yii\base\Object;
use yii\helpers\ArrayHelper;

/**
 * Class Jwt
 * Jwt的生成与验证
 * @package app\core\helps
 */
class Jwt extends Object
{

    private $_config;
    private $_userId;
    private $_iat;
    private $_exp;
    private $_header;
    private $_payload;
    private $_signature;

    /**
     * 配置初始化
     * Jwt constructor.
     */
    public function __construct($userid='')
    {
        $this->_config = \Yii::$app->params['JwtConfig'];
        $this->_userId = $userid;
    }

    /**
     * 获取Header
     * @return string base64化header
     */
    public function setHeader()
    {
        if (empty($this->_header)) {
            $this->_header = base64_encode(json_encode($this->_config['header']));
        }
        return $this->_header;
    }


    /**
     * 设置payload
     * iat: jwt的签发时间
     * exp: jwt的过期时间，这个过期时间必须要大于签发时间
     * jti: jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击
     * @param array $ext
     * @return string
     */
    public function setPayload($ext = [])
    {
        if (empty($this->_payload)) {
            //新生成payload
            $payload = array();
            $payload['iss'] = $this->getIss();
            $payload['sub'] = empty($this->_userId) ? 0 : $this->_userId;
            $payload['iat'] = $this->getIat();
            $payload['exp'] = $this->getExp();
            $payload['jti'] = $this->getJti($payload['iat'],$payload['exp'],$payload['sub']);
            $payload = array_merge($payload, $ext);
            $this->_payload = base64_encode(json_encode($payload));
        }
        return $this->_payload;
    }

    /**
     * 设置签名
     * @return string
     */
    public function setSignature(){
        if (empty($this->_signature)) {
            $this->_signature = $this->createSignature($this->setHeader(),$this->setPayload());
        }
        return $this->_signature;
    }


    /**
     * 创建Token
     * @param array $ext 额外的数组
     * @return string
     */
    public function createToken($ext = []){
        $this->setHeader();
        $this->setPayload($ext);
        $this->setSignature();
        $token =  $this->_header."." . $this->_payload . "." . $this->_signature;
        //如果启用redis 就保存token到redis
       /* if($this->_config['redis']){
            $this->saveTokenToRedis($token,$this->_signature,$this->_config['lease']);
        }*/
        \Yii::$app->session['time'] = $token;
        return $token;
    }



    /**
     * 生成签名
     * @param $header
     * @param $payload
     * @return string
     */
    public function createSignature($header,$payload){
        $src = $header . "." . $payload;
        return hash_hmac('sha256', $src, $this->getSecret());
    }

    /**
     * 获取签发时间
     * @return int 签发时间unix时间戳
     */

    public function getIat()
    {
        $this->_iat = empty($this->_iat) ? time() : $this->_iat;
        return $this->_iat;
    }

    /**获取到期时间
     * @return int token到期unix时间戳
     */
    public function getExp()
    {
        $this->_exp = empty($this->_exp) ? $this->getIat() + $this->_config['lease'] : $this->_exp;
        return $this->_exp;
    }

    /**
     * 获取Token唯一ID
     * @return bool|string
     */
    public function getJti($iat,$exp,$userId)
    {
        return md5($this->_userId . $this->getIat().$this->getExp());
    }

    /**
     * 验证Token唯一ID
     * @return bool|string
     */
    public function getnewJti($iat,$exp,$userId)
    {
        return md5($userId . $iat.$exp);
    }

    /**
     * @param $iat
     * @param $exp
     * @param $userId
     * @param $jti 需要验证身份标识
     * @return bool
     */
    public function checkJti($iat,$exp,$userId,$jti){
        $jtiR = $this->getnewJti($iat,$exp,$userId);
        if ($jtiR == $jti){
            return true;
        }else return false;
    }

    /**
     * 用户ID输入
     * @param $userId
     */
    public function setUserId($userId)
    {
        $this->_userId = $userId;
    }

    /**
     * 获取来源地址
     * @return mixed
     */
    public function getIss()
    {
        return $this->_config['iss'];
    }

    /**
     * 获取秘钥
     * @return mixed
     */
    public function getSecret()
    {
        return $this->_config['secret'];
    }







    /**
     * 检查签名
     * @param $header
     * @param $payload
     * @param $signature
     * @return bool
     */
    public function checkSignature($header,$payload,$signature){
        $signatureR = $this->createSignature($header,$payload);
        if ($signatureR == $signature){
            return true;
        }else return false;
    }



    /**
     * 保存token到redis
     * @param $token
     * @param $signature
     * @param $expire 时长
     */
    public function saveTokenToRedis($token,$signature,$expire=3600){
        $redis =\Yii::$app->redis;
        $redis->set($signature,$token);
        $redis->expire($signature,$expire);
    }






    //----------------------------------------------------------------------------
    //以下解密

    /**
     * 转码token
     * @param array $token
     * @return bool
     */
    public function encodeToken($token){
        //检查数组格式是否正确
        $tokenArray = explode('.',$token);
        //转码header
        $tokenArrayDecode['header']=$this->checkJson($tokenArray[0]);
        if(!is_object($tokenArrayDecode['header'])){
            return false;
        }
        //转码payload
        $tokenArrayDecode['payload']=$this->checkJson($tokenArray[1]);
        if(!is_object($tokenArrayDecode['payload'])){
            return false;
        }
        //signature 存入
        $tokenArrayDecode['signature']= $tokenArray[2];
        return $tokenArrayDecode;
    }

    /**
     * 对比数据
     * @param $payload
     * @return bool
     */
    public function checkPayload($payload){
        //检查时效
        if(!$this->checkExp($payload->iat,$payload->exp)){
            return false;

        }
        //检查签名
        if(!$this->checkJti($payload->iat,$payload->exp,$payload->sub,$payload->jti)){
            return false;
        }
        $this->_userId = $payload->sub;
        return true;
    }

    /**
     * 验证token
     * @param $token
     * @return bool 错误返回flase 正确返回userId
     */
    public function validateToken($token){
        //解码token
        $tokenArray = $this->encodeToken($token);
        $tokenBase = explode('.',$token);
        if (!is_array($tokenArray)){
            return false;
        }
        //检查payload是否正确
        if(!$this->checkPayload($tokenArray['payload'])){
            return false;
        }
        //检查签名是否正确
        if(!$this->checkSignature($tokenBase[0],$tokenBase[1],$tokenBase[2])){
            return false;
        }
        //如果redis开启，验证redis上的token
        /*if($this->_config['redis']){
            $redis = \Yii::$app->redis;
            if(!$redis->exists($tokenArray['signature'])||$redis->get($tokenArray['signature'])!=$token){
                return false;
            }
        }*/
        //return $tokenArray;

        return base64_decode($tokenBase[1]);
    }


    /**
     * 检查时效
     * @param $iat
     * @param $exp
     * @return bool
     */
    public function checkExp($iat,$exp){
        $now = time();
        if($now<$iat||$now>$exp){
            return false;
        }else return true;
    }

    /**
     * 检查是不是json 如果是返回数组
     * @param array $datas
     * @return array|bool
     */
    public function checkJson($data){
        $json = base64_decode($data);
       /* if(is_json($json)){*/
           return  json_decode($json);
       /* }else return false;*/
    }

}