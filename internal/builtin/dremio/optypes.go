package dremio

import "strconv"

// coreOperatorTypes maps the numeric operatorType of an operator profile to the
// name of UserBitShared.CoreOperatorType in dremio-protocol 24.1.0. The profile
// carries the number only. The list comes from the protocol jar of the
// 24.1.0 image.
var coreOperatorTypes = [...]string{
	0: "SINGLE_SENDER", 1: "BROADCAST_SENDER", 2: "FILTER", 3: "HASH_AGGREGATE", 4: "HASH_JOIN", 5: "MERGE_JOIN",
	6: "HASH_PARTITION_SENDER", 7: "LIMIT", 8: "MERGING_RECEIVER", 9: "ORDERED_PARTITION_SENDER", 10: "PROJECT",
	11: "UNORDERED_RECEIVER", 12: "RANGE_SENDER", 13: "SCREEN", 14: "SELECTION_VECTOR_REMOVER", 15: "STREAMING_AGGREGATE",
	16: "TOP_N_SORT", 17: "EXTERNAL_SORT", 18: "TRACE", 19: "UNION", 20: "OLD_SORT", 21: "PARQUET_ROW_GROUP_SCAN",
	22: "HIVE_SUB_SCAN", 23: "SYSTEM_TABLE_SCAN", 24: "MOCK_SUB_SCAN", 25: "PARQUET_WRITER", 26: "DIRECT_SUB_SCAN",
	27: "TEXT_WRITER", 28: "TEXT_SUB_SCAN", 29: "JSON_SUB_SCAN", 30: "INFO_SCHEMA_SUB_SCAN", 31: "COMPLEX_TO_JSON",
	32: "PRODUCER_CONSUMER", 33: "HBASE_SUB_SCAN", 34: "WINDOW", 35: "NESTED_LOOP_JOIN", 36: "AVRO_SUB_SCAN",
	37: "MONGO_SUB_SCAN", 38: "ELASTICSEARCH_SUB_SCAN", 39: "ELASTICSEARCH_AGGREGATOR_SUB_SCAN", 40: "FLATTEN",
	41: "EXCEL_SUB_SCAN", 42: "ARROW_SUB_SCAN", 43: "ARROW_WRITER", 44: "JSON_WRITER", 45: "VALUES_READER",
	46: "CONVERT_FROM_JSON", 47: "JDBC_SUB_SCAN", 48: "DICTIONARY_LOOKUP", 49: "WRITER_COMMITTER", 50: "ROUND_ROBIN_SENDER",
	51: "BOOST_PARQUET", 52: "ICEBERG_SUB_SCAN", 53: "TABLE_FUNCTION", 54: "DELTALAKE_SUB_SCAN", 55: "DIR_LISTING_SUB_SCAN",
	56: "ICEBERG_WRITER_COMMITTER", 57: "GRPC_WRITER", 58: "MANIFEST_WRITER", 59: "FLIGHT_SUB_SCAN",
	60: "BRIDGE_FILE_WRITER_SENDER", 61: "BRIDGE_FILE_READER_RECEIVER", 62: "BRIDGE_FILE_READER", 63: "ICEBERG_MANIFEST_WRITER",
	64: "ICEBERG_METADATA_FUNCTIONS_READER", 65: "ICEBERG_SNAPSHOTS_SUB_SCAN", 66: "JDBC_WRITER", 67: "ICEBERG_SIMPLE_WRITER",
}

// attemptStates names AttemptEvent.State, the states in the stateList of a profile.
var attemptStates = [...]string{
	0: "INVALID_STATE", 1: "PENDING", 2: "METADATA_RETRIEVAL", 3: "PLANNING", 4: "QUEUED", 5: "ENGINE_START",
	6: "EXECUTION_PLANNING", 7: "STARTING", 8: "RUNNING", 9: "COMPLETED", 10: "CANCELED", 11: "FAILED",
}

// queryStates names QueryResult.QueryState, the state of a profile.
var queryStates = [...]string{0: "STARTING", 1: "RUNNING", 2: "COMPLETED", 3: "CANCELED", 4: "FAILED", 5: "NO_LONGER_USED_1", 6: "ENQUEUED"}

func nameOf(names []string, n int, kind string) string {
	if n >= 0 && n < len(names) && names[n] != "" {
		return names[n]
	}
	return kind + "_" + strconv.Itoa(n)
}

func operatorTypeName(n int) string { return nameOf(coreOperatorTypes[:], n, "OPERATOR") }
