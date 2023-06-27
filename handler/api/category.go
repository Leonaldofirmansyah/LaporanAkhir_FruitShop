package api

import (
	"a21hc3NpZ25tZW50/model"
	"a21hc3NpZ25tZW50/service"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type CategoryAPI interface {
	AddCategory(c *gin.Context)
	UpdateCategory(c *gin.Context)
	DeleteCategory(c *gin.Context)
	GetCategoryByID(c *gin.Context)
	GetCategoryList(c *gin.Context)
}

type categoryAPI struct {
	categoryService service.CategoryService
}

func NewCategoryAPI(categoryRepo service.CategoryService) *categoryAPI {
	return &categoryAPI{categoryRepo}
}

func (ct *categoryAPI) AddCategory(c *gin.Context) {
	var newCategory model.Category
	if err := c.ShouldBindJSON(&newCategory); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Error: err.Error()})
		return
	}

	err := ct.categoryService.Store(&newCategory)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, model.SuccessResponse{Message: "add category success"})
}

func (ct *categoryAPI) UpdateCategory(c *gin.Context) {
	// Mendapatkan ID tugas dari parameter URL
	categoryID := c.Param("id")

	// cek jika id kosong
	if categoryID == "" {
		c.JSON(400, model.ErrorResponse{Error: "invalid Category ID"})
		return
	}

	// konvert id string ke type int
	id, err := strconv.Atoi(categoryID)
	if err != nil {
		c.JSON(400, model.ErrorResponse{Error: "invalid Category ID"})
		return
	}

	var categoryData model.Category

	if err := c.ShouldBindJSON(&categoryData); err != nil {
		c.JSON(400, model.ErrorResponse{Error: err.Error()})
		return
	}

	categoryData.ID = id

	err = ct.categoryService.Update(id, categoryData)
	if err != nil {
		c.JSON(500, model.ErrorResponse{Error: err.Error()})
	}

	c.JSON(200, gin.H{
		"message": "category update success",
	})
}

func (ct *categoryAPI) DeleteCategory(c *gin.Context) {
	categoryID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Error: "Invalid category ID"})
		return
	}

	err = ct.categoryService.Delete(categoryID)
	c.JSON(200, gin.H{
		"message": "category delete success",
	})
}

func (ct *categoryAPI) GetCategoryByID(c *gin.Context) {
	categoryID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Error: "Invalid category ID"})
		return
	}

	category, err := ct.categoryService.GetByID(categoryID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, category)
}

func (ct *categoryAPI) GetCategoryList(c *gin.Context) {
	categories, err := ct.categoryService.GetList()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, categories)
}
