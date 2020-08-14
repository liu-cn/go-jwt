package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)
//密钥
var jwtSecret = "hello"

type Claims struct {
	Username string `json:"username"`
	Password string `json:"password"`
	jwt.StandardClaims
}

//生成token
func GenerateToken(username,password string)(string,error){
	nowtime:=time.Now()
	expireTime:= nowtime.Add(3 *time.Hour)
	claims:=Claims{
		username,
		password,
		jwt.StandardClaims{
			ExpiresAt: expireTime.Unix(),
			Issuer: "mrliu",

		},
	}
	tokenClaims:=jwt.NewWithClaims(jwt.SigningMethodHS256,claims)
	token,err:=tokenClaims.SignedString([]byte(jwtSecret))

	return token,err

}
//解析token
func ParseToken(token string)(*Claims,error){
	tokenClaims,err:=jwt.ParseWithClaims(token,&Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret),nil
	})
	if tokenClaims!=nil {
		if claims,ok:=tokenClaims.Claims.(*Claims);ok&&tokenClaims.Valid{
			return claims,err
		}
	}
	return nil, err
}

//中间件验证token
func JWTAuth(c *gin.Context)  {
	token:=c.DefaultQuery("token","")
	if token ==""{
		c.JSON(http.StatusBadRequest,gin.H{
			"msg":"请求未携带token！",
		})
		c.Abort()
		return
	}
	claims,err:=ParseToken(token)
	if err != nil {
		c.JSON(http.StatusBadRequest,gin.H{
			"msg":err.Error(),
		})
		c.Abort()
		return
	}
	c.Set("claims",claims)
}


func main() {

	route := gin.Default()
	route.POST("/", JWTAuth,func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "hello world",
		})

	})

	route.POST("login", func(c *gin.Context) {
		username:=c.Query("username")
		password:=c.Query("password")
		fmt.Println(username)
		if username !=""||password!=""{
			if username=="admin"&&password=="123456" {
				token,err:=GenerateToken(username,password)
				if err != nil {
					c.JSON(http.StatusBadRequest,gin.H{
						"msg":"创建token失败",
					})
				}else {
					c.JSON(http.StatusOK,gin.H{
						"msg":"登录成功!",
						"username":username,
						"token":token,
					})
				}
			}else {
				c.JSON(http.StatusBadRequest,gin.H{
					"msg":"账号或密码输入错误！",
				})
			}
		}else {
			c.JSON(http.StatusBadRequest,gin.H{
				"msg":"账号或密码没有输入！",
			})
		}

	})

	route.Run() // listen and serve on 0.0.0.0:8080
}