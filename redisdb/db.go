package redisdb

import (
	"fmt"
	"github.com/gomodule/redigo/redis"
)

func RedisConnect()  {
	fmt.Println("hello world")
	red,err:=redis.Dial("tcp","106.53.69.86:6379")
	if err!=nil{
		fmt.Println("redis Dial err:",err)
		return
	}
	defer red.Close()
	if _,err:=red.Do("SET","age","18");err!=nil{
		fmt.Println("redis set err:",err)
		return
	}
	if age,err:=redis.String(red.Do("GET","age")); err!=nil{
		fmt.Println("redis get err :",err)
		return
	}else {
		fmt.Println(age)
	}
	
}