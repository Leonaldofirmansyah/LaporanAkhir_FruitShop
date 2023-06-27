package middleware

import (
	"a21hc3NpZ25tZW50/model"
	"github.com/golang-jwt/jwt"

	"github.com/gin-gonic/gin"
)

func Auth() gin.HandlerFunc {
	return gin.HandlerFunc(func(ctx *gin.Context) {
		//get token from cookie
		token, err := ctx.Cookie("session_token")
        if err != nil {
			contentType := ctx.GetHeader("Content-Type")
		if contentType != "application/json" {
			ctx.AbortWithStatusJSON(303, gin.H{
                "error": "Invalid Content-Type",
            })
            return
		}
            ctx.AbortWithStatusJSON(401, gin.H{
                "error": "Unauthorized",
            })
            return
        }
		

		//validate token
		claims := &model.Claims{}

		//parse jwt token ke claim
		tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
            return model.JwtKey, nil
        })
		
		if err != nil {
			ctx.AbortWithStatusJSON(400, gin.H{
                "message": "Unauthorized",
            })
            return
		}
		//token is valid or not based on claims.valid
		if !tkn.Valid {
			ctx.AbortWithStatusJSON(401, gin.H{
				"error": "token is invalid",
			})

			return
		}
		//set claims to context
		ctx.Set("email", claims.Email)

		ctx.Next()
	})
}
