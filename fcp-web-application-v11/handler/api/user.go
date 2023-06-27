package api

import (
	"a21hc3NpZ25tZW50/model"
	"a21hc3NpZ25tZW50/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

type UserAPI interface {
	Register(c *gin.Context)
	Login(c *gin.Context)
	GetUserTaskCategory(c *gin.Context)
}

type userAPI struct {
	userService service.UserService
}

func NewUserAPI(userService service.UserService) *userAPI {
	return &userAPI{userService}
}

func (u *userAPI) Register(c *gin.Context) {
	var user model.UserRegister

	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, model.NewErrorResponse("invalid decode json"))
		return
	}

	if user.Email == "" || user.Password == "" || user.Fullname == "" {
		c.JSON(http.StatusBadRequest, model.NewErrorResponse("register data is empty"))
		return
	}

	var recordUser = model.User{
		Fullname: user.Fullname,
		Email:    user.Email,
		Password: user.Password,
	}

	recordUser, err := u.userService.Register(&recordUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.NewErrorResponse("error internal server"))
		return
	}

	c.JSON(http.StatusCreated, model.NewSuccessResponse("register success"))
}

func (u *userAPI) Login(c *gin.Context) {
	var userlogin model.UserLogin
	var user model.User

	if err := c.BindJSON(&userlogin); err != nil {
		c.JSON(http.StatusBadRequest, model.NewErrorResponse("invalid decode json"))
		return
	}

	if userlogin.Email == "" || userlogin.Password == "" {
        c.JSON(http.StatusBadRequest, model.NewErrorResponse("invalid decode json"))
        return
    }
	
	user.Email = userlogin.Email
	user.Password = userlogin.Password

	userLogin, err := u.userService.Login(&user)

	if err!= nil {
        c.JSON(http.StatusInternalServerError, model.NewErrorResponse("error internal server"))
        return
    }

	c.SetCookie("session_token", *userLogin, 3600, "/", "localhost", false, true)

    c.JSON(http.StatusOK, gin.H{
		"user_id": user.ID,
		"message": "login success",
	})
}

func (u *userAPI) GetUserTaskCategory(c *gin.Context) {
	userTask, err := u.userService.GetUserTaskCategory()
	if err!= nil {
			c.JSON(http.StatusInternalServerError, model.NewErrorResponse("error internal server"))
			return
		}
	c.JSON(http.StatusOK, userTask)
}
