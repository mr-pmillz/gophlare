/*
No need for Postgres interaction but since already wrote this code, going to leave it here for now.
*/

package bloodhound

// type PostGresDB struct {
//	Conn *gorm.DB
//	Options *PostGresDBOptions
// }

//// PostGresDBOptions ...
// type PostGresDBOptions struct {
//	Host     string
//	Port     string
//	User     string
//	Password string
//	DBName   string
// }

//// NewPostGresDBOptions creates a new PostGresDBOptions instance with the provided connection parameters
// func NewPostGresDBOptions(host, port, user, password, dbName string) *PostGresDBOptions {
//	return &PostGresDBOptions{
//		Host:     host,
//		Port:     port,
//		User:     user,
//		Password: password,
//		DBName:   dbName,
//	}
// }

//// NewPostGresDBConnection ...
// func NewPostGresDBConnection(postGresOpts *PostGresDBOptions) (*PostGresDB, error) {
//	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable TimeZone=America/Detroit", postGresOpts.Host, postGresOpts.Port, postGresOpts.User, postGresOpts.Password, postGresOpts.DBName)
//	db, err := gorm.Open(postgres.New(postgres.Config{
//		DSN:                  dsn, // data source name, refer https://github.com/jackc/pgx
//		PreferSimpleProtocol: true,                                                                                                  // disables implicit prepared statement usage. By default pgx automatically uses the extended protocol
//	}), &gorm.Config{})
//	if err != nil {
//		return nil, utils.LogError(err)
//	}
//
//	return &PostGresDB{
//		Conn:    db,
//		Options: postGresOpts,
//	}, nil
// }

//// GetTables ...
// func (pg *PostGresDB) GetTables() ([]string, error) {
//	tables := make([]string, 0)
//	result := pg.Conn.Table("information_schema.tables").
//		Where("table_schema = ?", "public").
//		Pluck("table_name", &tables)
//	if result.Error != nil {
//		return nil, utils.LogError(result.Error)
//	}
//
//	return tables, nil
// }
