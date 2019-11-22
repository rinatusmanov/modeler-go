package modeler

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"regexp"
	"strings"

	"github.com/jinzhu/gorm"
)

type modelerStruct struct {
	models                        map[string]reflect.Type
	modelsSlices                  map[string]reflect.Type
	listOfModels                  map[string]interface{}
	byteSlListOfModels            []byte
	byteSlListOfModelsName        []byte
	byteSlListOfModelDescriptions []byte
	db                            *gorm.DB
	concurrency                   bool
	Handler                       http.Handler
	acl                           ALCFunc
}

// ALCFunc Функция проверки доступа к действиям
type ALCFunc func(model string, action string, r *http.Request, request RequestStruct) bool

// ResponseStruct ответ
type ResponseStruct struct {
	Code        uint64      `json:"code"`
	Result      interface{} `json:"result"`
	Error       string      `json:"err"`
	Message     string      `json:"msg"`
	Notice      []string    `json:"notice"`
	Concurrency interface{} `json:"concurrency"`
}

// ListResult Стандартный отверт для листинга
type ListResult struct {
	Result interface{} `json:"result"`
	Count  uint64      `json:"count"`
}

// RequestStruct Запрос
type RequestStruct struct {
	Model       string      `json:"model"`
	Data        interface{} `json:"data"`
	model       interface{}
	modelsSlice interface{}
	body        string
	TranVars    *map[string]string
}

type FieldStructure struct {
	Field      string `json:"field"`
	TypeName   string `json:"type_name"`
	IsNullable bool   `json:"is_nullable"`
	IsArray    bool   `json:"is_array"`
	IsTitle    bool   `json:"is_title"`
	Position   uint64 `json:"position"`
}

type Model struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Link        string           `json:"link"`
	Fields      []FieldStructure `json:"fields"`
}

func createStructModel(pointer interface{}, link string) (model Model) {
	val := reflect.TypeOf(pointer).Elem()
	model.Name = val.Name()
	model.Link = link
	for i := 0; i < val.NumField(); i++ {
		var fieldStructure = FieldStructure{IsNullable: false, IsArray: false, Position: uint64(i + 1)}
		field := val.Field(i)
		fieldStructure.Field = field.Name
		if field.Type.Kind() == reflect.Ptr {
			fieldStructure.TypeName = field.Type.Elem().Name()
			fieldStructure.IsNullable = true
		} else {
			fieldStructure.TypeName = field.Type.Name()
		}
		if field.Type.Kind() == reflect.Slice {
			fieldStructure.TypeName = field.Type.Elem().Name()
			fieldStructure.IsArray = true
		}
		tags := strings.Split(field.Tag.Get("modeler"), ";")
		for _, tag := range tags {
			switch tag {
			case "title":
				fieldStructure.IsTitle = true
			default:
				if tag != "" {
					model.Description = tag
				}
			}
		}
		model.Fields = append(model.Fields, fieldStructure)
	}
	return
}

func (m *modelerStruct) createTransactionAndAddVars(request RequestStruct) (tx *gorm.DB) {
	tx = m.db.Begin()
	for key, value := range *request.TranVars {
		tx.Exec(fmt.Sprintf(`SELECT set_config('myapp.%v', '%v', true);`, key, value))
	}
	return
}
func addVarsToTransacion(tx *gorm.DB, vars map[string]string) {
	for key, value := range vars {
		tx.Exec(fmt.Sprintf(`SELECT set_config('myapp.%v', '%v', true);`, key, value))
	}
}

func (m *modelerStruct) Concurrency(concurrency bool) *modelerStruct {
	m.concurrency = concurrency
	return m
}

type listStruct struct {
	Data struct {
		Pattern       string
		PatternFields []string
		Count         uint64
		Page          uint64
		OrderByFields []string
		OrderDesc     bool
		Preloads      []string
	}
}

func (m *modelerStruct) listPattern(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	var (
		request   = r.Context().Value(RequestStruct{}).(RequestStruct)
		byteSl    []byte
		list      listStruct
		count     uint64
		whereData []interface{}
		whereStr  []string
	)
	defer func() {
		w.Write(byteSl)
	}()
	json.Unmarshal([]byte(request.body), &list)
	if list.Data.Count != 0 {
		db = db.Limit(list.Data.Count)
		if list.Data.Page != 0 {
			db = db.Offset(list.Data.Count * list.Data.Page)
		}
	}
	if len(list.Data.OrderByFields) > 0 {
		var order = "asc"
		if list.Data.OrderDesc {
			order = "desc"
		}
		var fields = []string{}
		for index := 0; index < len(list.Data.OrderByFields); index++ {
			fields = append(fields, gorm.ToColumnName(list.Data.OrderByFields[index]))
		}
		fields[0] += " " + order
		db = db.Order(strings.Join(fields, ",") + " ")
	}
	if len(list.Data.PatternFields) > 0 && list.Data.Pattern != "" {
		for i := 0; i < len(list.Data.PatternFields); i++ {
			whereData = append(whereData, "%"+list.Data.Pattern+"%")
			whereStr = append(whereStr, "CAST("+gorm.ToColumnName(list.Data.PatternFields[i])+" as TEXT) LIKE ?")
		}
	}
	for index := 0; index < len(list.Data.Preloads); index++ {
		db = db.Preload(list.Data.Preloads[index])
	}
	if m.concurrency {
		db = db.Select("*, xmin")
	}

	db.Where(strings.Join(whereStr, " OR "), whereData...).Find(request.modelsSlice)
	m.db.Where(strings.Join(whereStr, " OR "), whereData...).Model(request.model).Count(&count)
	byteSl, _ = json.Marshal(&ResponseStruct{Code: 200, Result: ListResult{Result: request.modelsSlice, Count: count}})
}

// Получить список
func (m *modelerStruct) List(w http.ResponseWriter, r *http.Request) {
	m.listPattern(w, r, m.db)
}

// Получить список c удаленными записями
func (m *modelerStruct) ListUnscoped(w http.ResponseWriter, r *http.Request) {
	m.listPattern(w, r, m.db.Unscoped())
}

// Получить список удаленных записей
func (m *modelerStruct) ListDeleted(w http.ResponseWriter, r *http.Request) {
	m.listPattern(w, r, m.db.Unscoped().Where(whereDeleted))
}

// Получить список всех поддерживаемых моделей с их структурой
func (m *modelerStruct) ListModels(w http.ResponseWriter, r *http.Request) {
	w.Write(m.byteSlListOfModels)
}

// Получить список имен поддержываемых моделей
func (m *modelerStruct) ListNamesOfModels(w http.ResponseWriter, r *http.Request) {
	w.Write(m.byteSlListOfModelsName)
}

// Получить список имен поддержываемых моделей
func (m *modelerStruct) ListModelDescription(w http.ResponseWriter, r *http.Request) {
	w.Write(m.byteSlListOfModelDescriptions)
}

type getbyidStruct struct {
	Data struct {
		ID       string
		Preloads []string
	}
}

// Получить по ID
func (m *modelerStruct) GetByID(w http.ResponseWriter, r *http.Request) {
	var request = r.Context().Value(RequestStruct{}).(RequestStruct)
	var byteSl = byteSlNotInsertID
	defer func() {
		w.Write(byteSl)
	}()
	var getbyid getbyidStruct
	json.Unmarshal([]byte(request.body), &getbyid)
	var ID = getbyid.Data.ID
	if ID == "" {
		return
	}
	db := m.db.Unscoped()
	if m.concurrency {
		db = db.Select("*, xmin")
	}
	for index := 0; index < len(getbyid.Data.Preloads); index++ {
		db = db.Preload(getbyid.Data.Preloads[index])
	}
	db.
		Where(gorm.ToColumnName("ID")+" = ?", ID).
		Find(request.model)
	byteSl, _ = json.Marshal(&ResponseStruct{Code: 200, Result: request.model})
}

// создать запись в БД
func (m *modelerStruct) Create(w http.ResponseWriter, r *http.Request) {
	var request = r.Context().Value(RequestStruct{}).(RequestStruct)
	jsoned, _ := json.Marshal(request.Data)
	var byteSl = byteSlModelStructInCorrect
	err := json.Unmarshal(jsoned, request.model)
	if err == nil {
		errDb := func() error {
			tx := m.db.Begin()
			defer func() {
				if r := recover(); r != nil {
					tx.Rollback()
				} else {
					tx.Commit()
				}
			}()
			addVarsToTransacion(tx, (*request.TranVars))
			return tx.
				Create(request.model).Error
		}()
		if errDb == nil {
			db := m.db
			if m.concurrency {
				db = m.db.Select("*, xmin")
			}
			db.Find(request.model)
			byteSl, _ = json.Marshal(&ResponseStruct{Code: 200, Result: request.model})
		} else {
			byteSl = dbErr(errDb.Error())
		}

	}
	w.Write(byteSl)
}

type concurencyStruct struct {
	Data struct {
		ID   string
		Xmin uint64
	}
	Associations []string
}

// getXminID
// result 0 Ошибка по ID 1 Корректное завершение 10 Ошибка конкуренции
func (m *modelerStruct) getXminID(str string) (id string, xmin uint64, result uint64, byteAr []byte, associations []string) {
	var concurency concurencyStruct
	json.Unmarshal([]byte(str), &concurency)
	associations = concurency.Associations
	if concurency.Data.ID == "" {
		byteAr = byteSlNotInsertID
		return
	}
	id = concurency.Data.ID
	if m.concurrency && concurency.Data.Xmin == 0 {
		result = 10
		byteAr = byteSlNotInsertXmin
		return
	}
	xmin, result, byteAr = concurency.Data.Xmin, 1, []byte{}
	return
}

// изменить запись в БД
func (m *modelerStruct) Change(w http.ResponseWriter, r *http.Request) {
	var (
		request      = r.Context().Value(RequestStruct{}).(RequestStruct)
		byteSl       = byteSlModelStructInCorrect
		id           string
		xmin         uint64
		ok           uint64
		errDb        error
		jsoned       []byte
		associations []string
	)
	defer func() {
		w.Write(byteSl)
	}()
	id, xmin, ok, byteSl, associations = m.getXminID(request.body)
	if ok != 1 {
		return
	}
	db := m.db
	if m.concurrency {
		db = db.Where(gorm.ToColumnName("ID")+" = ? AND xmin = ?", id, xmin)
	} else {
		db = db.Where(gorm.ToColumnName("ID")+" = ?", id)
	}
	errDb = db.Find(request.model).Error
	if errDb != nil {
		if m.concurrency {
			errDb = m.db.Select("*, xmin").Where(gorm.ToColumnName("ID")+" = ?", id).Find(request.model).Error
			if errDb == nil {
				byteSl, _ = json.Marshal(&ResponseStruct{Code: 602, Error: "Ошибка конкуренции данных", Concurrency: request.model})
				return
			}
		}
		byteSl = dbErr(errDb.Error())
		return
	}
	saveError := func() error {
		tx := m.db.Debug().Begin()
		defer func() {
			if r := recover(); r != nil {
				tx.Rollback()
			} else {
				tx.Commit()
			}
		}()
		addVarsToTransacion(tx, (*request.TranVars))
		for index := 0; index < len(associations); index++ {
			tx.Model(request.model).Association(associations[index]).Clear()
		}
		jsoned, _ = json.Marshal(request.Data)
		json.Unmarshal(jsoned, request.model)
		return tx.
			Save(request.model).Error

	}()
	if saveError != nil {
		byteSl = dbErr(saveError.Error())
		return
	}
	db = m.db
	if m.concurrency {
		db = db.Select("*, xmin")
	}
	db.Find(request.model)
	byteSl, _ = json.Marshal(&ResponseStruct{Code: 200, Result: request.model})
}

// удалить запись в БД
func (m *modelerStruct) Delete(w http.ResponseWriter, r *http.Request) {
	var (
		request = r.Context().Value(RequestStruct{}).(RequestStruct)
		byteSl  = byteSlModelStructInCorrect
		id      string
		xmin    uint64
		ok      uint64
		errDb   error
	)
	defer func() {
		w.Write(byteSl)
	}()
	id, xmin, ok, byteSl, _ = m.getXminID(request.body)
	if ok == 0 {
		return
	}
	db := m.db
	if m.concurrency {
		db = db.Where(gorm.ToColumnName("ID")+" = ? AND xmin = ?", id, xmin)
	} else {
		db = db.Where(gorm.ToColumnName("ID")+" = ?", id)
	}
	errDb = db.Find(request.model).Error
	if errDb != nil {
		if m.concurrency {
			errDb = m.db.Select("*, xmin").Where(gorm.ToColumnName("ID")+" = ? AND deleted_at is NULL", id).Find(request.model).Error
			if errDb == nil {
				byteSl, _ = json.Marshal(&ResponseStruct{Code: 602, Error: "Ошибка конкуренции данных", Concurrency: request.model})
				return
			}
		}
		byteSl = dbErr(errDb.Error())
		return
	}
	errDb = func() error {
		tx := m.db.Begin()
		defer func() {
			if r := recover(); r != nil {
				tx.Rollback()
			} else {
				tx.Commit()
			}
		}()
		addVarsToTransacion(tx, (*request.TranVars))
		return tx.
			Delete(request.model).Error
	}()
	if errDb != nil {
		byteSl = dbErr(errDb.Error())
	} else {
		db := m.db.Unscoped()
		if m.concurrency {
			db = db.Select("*, xmin")
		}
		db.Where("deleted_at is not NULL").Find(request.model)
		byteSl, _ = json.Marshal(&ResponseStruct{Code: 200, Result: request.model})
	}
}

// восстановить запись в БД
func (m *modelerStruct) Restore(w http.ResponseWriter, r *http.Request) {
	var (
		request = r.Context().Value(RequestStruct{}).(RequestStruct)
		byteSl  = byteSlModelStructInCorrect
		id      string
		xmin    uint64
		ok      uint64
		errDb   error
	)
	defer func() {
		w.Write(byteSl)
	}()
	id, xmin, ok, byteSl, _ = m.getXminID(request.body)
	if ok == 0 {
		return
	}
	db := m.db
	if m.concurrency {
		db = db.Where(gorm.ToColumnName("ID")+" = ? AND xmin = ? AND deleted_at is not NULL", id, xmin)
	} else {
		db = db.Where(gorm.ToColumnName("ID")+" = ? AND deleted_at is not NULL", id)
	}
	errDb = db.Unscoped().Find(request.model).Error
	if errDb != nil {
		if m.concurrency {
			errDb = m.db.Unscoped().Select("*, xmin").Where(gorm.ToColumnName("ID")+" = ? AND deleted_at is not NULL", id).Find(request.model).Error
			if errDb == nil {
				byteSl, _ = json.Marshal(&ResponseStruct{Code: 602, Error: "Ошибка конкуренции данных", Concurrency: request.model})
				return
			}
		}
		byteSl = dbErr(errDb.Error())
		return
	}
	errDb = func() error {
		tx := m.db.Begin()
		defer func() {
			if r := recover(); r != nil {
				tx.Rollback()
			} else {
				tx.Commit()
			}
		}()
		addVarsToTransacion(tx, (*request.TranVars))
		return tx.Unscoped().Model(request.model).UpdateColumn("deleted_at", nil).Error
	}()
	if errDb != nil {
		byteSl = dbErr(errDb.Error())
	} else {
		db := m.db.Unscoped()
		if m.concurrency {
			db = db.Select("*, xmin")
		}
		db.Find(request.model)
		byteSl, _ = json.Marshal(&ResponseStruct{Code: 200, Result: request.model})
	}
}

var (
	regexpOnlyDigitsAndLetters = regexp.MustCompile(`[A-Za-z0-9]`)
	whereDeleted               = gorm.ToColumnName("DeletedAt") + " is not  NULL"
	// ByteSlNotCorrectRequest Не корректный формат запроса
	ByteSlNotCorrectRequest, _    = json.Marshal(&ResponseStruct{Code: 500, Error: "Не корректный формат запроса"})
	byteSlModelNotFound, _        = json.Marshal(&ResponseStruct{Code: 501, Error: "Не найдена модель"})
	byteSlModelStructInCorrect, _ = json.Marshal(&ResponseStruct{Code: 502, Error: "Не правильная структура модели"})
	byteSlNotInsertID, _          = json.Marshal(&ResponseStruct{Code: 503, Error: "Нет ID"})
	byteSlNotInsertXmin, _        = json.Marshal(&ResponseStruct{Code: 504, Error: "Нет Xmin"})

	_, _                       = json.Marshal(&ResponseStruct{Code: 600, Error: "Ошибка БД"})
	byteSlModelNotFoundAtDB, _ = json.Marshal(&ResponseStruct{Code: 601, Error: "Сущность не найдена в БД"})
	_, _                       = json.Marshal(&ResponseStruct{Code: 602, Error: "Ошибка конкуренции данных"})

	byteSlAccessDenied, _      = json.Marshal(&ResponseStruct{Code: 700, Error: "Нет прав доступа на данную операцию"})
	byteSlRequestNotCorrect, _ = json.Marshal(&ResponseStruct{Code: 800, Error: "Не корректный запрос"})
)

func dbErr(message string) []byte {
	res, _ := json.Marshal(&ResponseStruct{Code: 600, Error: "Ошибка БД", Message: message})
	return res
}

type postgresFunc func(tableName string, columnName string) bool

// NewModeler Создает мукс с modeler
func NewModeler(inDataDB *gorm.DB, acl ALCFunc, inDataListOfModels map[string]interface{}) *modelerStruct {
	mux := http.NewServeMux()
	var (
		listOfModelsName   = []string{}
		models             = make(map[string]reflect.Type)
		modelsSlices       = make(map[string]reflect.Type)
		modelDescriptionSl []Model
	)
	for title, pnt := range inDataListOfModels {
		listOfModelsName = append(listOfModelsName, title)
		models[title] = reflect.TypeOf(pnt).Elem()
		modelsSlices[title] = reflect.SliceOf(models[title])
		modelDescriptionSl = append(modelDescriptionSl, createStructModel(pnt, title))
	}
	var (
		byteSlListOfModelsName, _        = json.Marshal(&ResponseStruct{Code: 200, Result: listOfModelsName})
		byteSlListOfModels, _            = json.Marshal(&ResponseStruct{Code: 200, Result: inDataListOfModels})
		byteSlListOfModelDescriptions, _ = json.Marshal(&ResponseStruct{Code: 200, Result: modelDescriptionSl})
	)
	var modeler = modelerStruct{
		acl:                           acl,
		db:                            inDataDB,
		listOfModels:                  inDataListOfModels,
		models:                        models,
		modelsSlices:                  modelsSlices,
		byteSlListOfModelsName:        byteSlListOfModelsName,
		byteSlListOfModels:            byteSlListOfModels,
		byteSlListOfModelDescriptions: byteSlListOfModelDescriptions,
	}
	type muxStruct struct {
		fun   func(w http.ResponseWriter, r *http.Request)
		title string
	}
	mapOffunc := map[string]muxStruct{
		"/list":                   {modeler.List, "List"},
		"/list_unscoped":          {modeler.ListUnscoped, "ListUnscoped"},
		"/list_deleted":           {modeler.ListDeleted, "ListDeleted"},
		"/list_models":            {modeler.ListModels, "ListModels"},
		"/list_names_of_models":   {modeler.ListNamesOfModels, "ListNamesOfModels"},
		"/list_model_description": {modeler.ListModelDescription, "ListModelDescription"},
		"/get_by_id":              {modeler.GetByID, "GetByID"},
		"/create":                 {modeler.Create, "Create"},
		"/change":                 {modeler.Change, "Change"},
		"/delete":                 {modeler.Delete, "Delete"},
		"/restore":                {modeler.Restore, "Restore"},
	}
	for pattern, fun := range mapOffunc {
		mux.HandleFunc(pattern, fun.fun)
	}
	modeler.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Key, User-Identity")
		w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, PATCH, POST, DELETE, OPTIONS")
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		var request RequestStruct
		html, _ := ioutil.ReadAll(r.Body)
		err := json.Unmarshal(html, &request)
		if err != nil || request.Model == "" {
			w.Write(ByteSlNotCorrectRequest)
		} else {
			if model, ok := modeler.models[request.Model]; ok {
				modelSlice, _ := modeler.modelsSlices[request.Model]
				request.body = string(html)
				request.model = reflect.New(model).Interface()
				request.modelsSlice = reflect.New(modelSlice).Interface()
				_, pattern := mux.Handler(r)
				action, ok := mapOffunc[pattern]
				if ok {
					vars := make(map[string]string)
					request.TranVars = &vars
					if acl(request.Model, action.title, r, request) {
						ctx := context.WithValue(r.Context(), RequestStruct{}, request)
						mux.ServeHTTP(w, r.WithContext(ctx))
					} else {
						w.Write(byteSlAccessDenied)
					}
				}
			} else {
				w.Write(byteSlModelNotFound)
			}
		}
	})
	return &modeler
}
