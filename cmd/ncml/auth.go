package main

import (
	"fmt"

	c "github.com/pvik/ncml/internal/config"

	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
)

func jwtAuth(tokenString string) bool {

	// Parse takes the token string and a function for looking up the key
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(c.AppConf.JWTConfig.Secret), nil
	})
	if err != nil {
		log.Errorf("parse token err: %s", err)
		return false
	}

	if _claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		log.Debugf("claims: %+v", _claims)
		// if JWT has exp claim, check if it has not expired
		//  jwt.Parse verifies token expiry

		// httphelper.RespondwithJSON(w, 200, claims)
		return true
	}

	return false
}
