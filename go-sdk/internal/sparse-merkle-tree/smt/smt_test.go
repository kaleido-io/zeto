// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package smt

import (
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"os"
	"testing"

	"github.com/hyperledger-labs/zeto/go-sdk/internal/crypto"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/sparse-merkle-tree/node"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/sparse-merkle-tree/storage"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/testutils"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type MerkleTreeTestSuite struct {
	suite.Suite
	db     core.Storage
	dbfile *os.File
	gormDB *gorm.DB
}

type testSqlProvider struct {
	db *gorm.DB
}

func (p *testSqlProvider) DB() *gorm.DB {
	return p.db
}

func (p *testSqlProvider) Close() {}

func (s *MerkleTreeTestSuite) SetupTest() {
	logrus.SetLevel(logrus.DebugLevel)
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(s.T(), err)
	s.dbfile = dbfile
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			LogLevel:                  logger.Info, // Log level
			IgnoreRecordNotFoundError: true,        // Ignore ErrRecordNotFound error for logger
			ParameterizedQueries:      false,       // Don't include params in the SQL log
			Colorful:                  true,        // Disable color
		},
	)
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{Logger: newLogger})
	assert.NoError(s.T(), err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(s.T(), err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(s.T(), err)

	provider := &testSqlProvider{db: db}
	s.db = storage.NewSqlStorage(provider, "test_1")
	s.gormDB = db
}

func (s *MerkleTreeTestSuite) TearDownTest() {
	os.Remove(s.dbfile.Name())
}

func (s *MerkleTreeTestSuite) TestNewMerkleTree() {
	mt, err := NewMerkleTree(s.db, 64)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), 0, mt.Root().BigInt().Cmp(big.NewInt(0)))
}

func (s *MerkleTreeTestSuite) TestAddNode() {
	mt, err := NewMerkleTree(s.db, 10)
	assert.NoError(s.T(), err)

	x, _ := new(big.Int).SetString("9198063289874244593808956064764348354864043212453245695133881114917754098693", 10)
	y, _ := new(big.Int).SetString("3600411115173311692823743444460566395943576560299970643507632418781961416843", 10)
	alice := &babyjub.PublicKey{
		X: x,
		Y: y,
	}
	salt1, _ := new(big.Int).SetString("43c49e8ba68a9b8a6bb5c230a734d8271a83d2f63722e7651272ebeef5446e", 16)
	utxo1 := node.NewFungible(big.NewInt(10), alice, salt1)
	idx1, err := utxo1.CalculateIndex()
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "11a22e32f5010d3658d1da9c93f26b77afe7a84346f49eae3d1d4fc6cd0a36fd", idx1.BigInt().Text(16))

	n1, err := node.NewLeafNode(utxo1)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(n1)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "525b60b382630ee7825bea84fb8808c13ede1fb827fe683cd5b14d76f6ac6d0b", mt.Root().Hex())

	// adding a 2nd node to test the tree update and branch nodes
	salt2, _ := new(big.Int).SetString("19b965f7629e4f0c4bd0b8f9c87f17580f18a32a31b4641550071ee4916bbbfc", 16)
	utxo2 := node.NewFungible(big.NewInt(20), alice, salt2)
	idx2, err := utxo2.CalculateIndex()
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "197b0dc3f167041e03d3eafacec1aa3ab12a0d7a606581af01447c269935e521", idx2.BigInt().Text(16))
	n2, err := node.NewLeafNode(utxo2)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(n2)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "c432caeb6448cb10bf8b449704f0fc79d84723b5aadeaf6f1b73cf00fe94c22f", mt.Root().Hex())

	// adding a 3rd node to test the tree update and branch nodes with a left/right child node
	salt3, _ := new(big.Int).SetString("9b0b93df975547e430eabff085a77831b8fcb6b5396e6bb815fda8d14125370", 16)
	utxo3 := node.NewFungible(big.NewInt(30), alice, salt3)
	idx3, err := utxo3.CalculateIndex()
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "2d46e23e813abf1fdabffe3ff22a38ebf6bb92d7c381463bee666eb010289fd5", idx3.BigInt().Text(16))
	n3, err := node.NewLeafNode(utxo3)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(n3)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "bf8409a4a6c7366bc64c154d3c2f40a8c3c5ddb0f1d47c41336d97ff27640502", mt.Root().Hex())

	// adding a 4th node to test the tree update and branch nodes with the other left/right child node
	salt4, _ := new(big.Int).SetString("194ec10ec96a507c7c9b60df133d13679b874b0bd6ab89920135508f55b3f064", 16)
	utxo4 := node.NewFungible(big.NewInt(40), alice, salt4)
	idx4, err := utxo4.CalculateIndex()
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "887884c3421b72f8f1991c64808262da78732abf961118d02b0792bd421521f", idx4.BigInt().Text(16))
	n4, err := node.NewLeafNode(utxo4)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(n4)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "abacf46f5217552ee28fe50b8fd7ca6aa46daeb9acf9f60928654c3b1a472f23", mt.Root().Hex())

	// test storage persistence
	rawDB := mt.(*sparseMerkleTree).db
	rootIdx, err := rawDB.GetRootNodeIndex()
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "abacf46f5217552ee28fe50b8fd7ca6aa46daeb9acf9f60928654c3b1a472f23", rootIdx.Hex())

	// test storage persistence across tree creation
	mt2, err := NewMerkleTree(s.db, 10)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "abacf46f5217552ee28fe50b8fd7ca6aa46daeb9acf9f60928654c3b1a472f23", mt2.Root().Hex())
}

func (s *MerkleTreeTestSuite) TestAddNodeFailExistingKey() {
	mt, err := NewMerkleTree(s.db, 10)
	assert.NoError(s.T(), err)

	x, _ := new(big.Int).SetString("9198063289874244593808956064764348354864043212453245695133881114917754098693", 10)
	y, _ := new(big.Int).SetString("3600411115173311692823743444460566395943576560299970643507632418781961416843", 10)
	alice := &babyjub.PublicKey{
		X: x,
		Y: y,
	}
	salt1, _ := new(big.Int).SetString("43c49e8ba68a9b8a6bb5c230a734d8271a83d2f63722e7651272ebeef5446e", 16)
	utxo1 := node.NewFungible(big.NewInt(10), alice, salt1)
	idx1, err := utxo1.CalculateIndex()
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "11a22e32f5010d3658d1da9c93f26b77afe7a84346f49eae3d1d4fc6cd0a36fd", idx1.BigInt().Text(16))

	n1, err := node.NewLeafNode(utxo1)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(n1)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "525b60b382630ee7825bea84fb8808c13ede1fb827fe683cd5b14d76f6ac6d0b", mt.Root().Hex())

	err = mt.AddLeaf(n1)
	assert.EqualError(s.T(), err, "key already exists")
}

func (s *MerkleTreeTestSuite) TestGenerateProof() {
	const levels = 10
	mt, _ := NewMerkleTree(s.db, levels)

	alice := testutils.NewKeypair()
	utxo1 := node.NewFungible(big.NewInt(10), alice.PublicKey, big.NewInt(12345))
	node1, err := node.NewLeafNode(utxo1)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(node1)
	assert.NoError(s.T(), err)

	utxo2 := node.NewFungible(big.NewInt(10), alice.PublicKey, big.NewInt(12346))
	node2, err := node.NewLeafNode(utxo2)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(node2)
	assert.NoError(s.T(), err)

	target1 := node1.Index().BigInt()

	utxo3 := node.NewFungible(big.NewInt(10), alice.PublicKey, big.NewInt(12347))
	node3, err := node.NewLeafNode(utxo3)
	assert.NoError(s.T(), err)
	target2 := node3.Index().BigInt()
	proofs, foundValues, err := mt.GenerateProofs([]*big.Int{target1, target2}, mt.Root())
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), target1, foundValues[0])
	assert.True(s.T(), proofs[0].(*proof).existence)
	valid := VerifyProof(mt.Root(), proofs[0], node1)
	assert.True(s.T(), valid)
	assert.False(s.T(), proofs[1].(*proof).existence)

	proof3, err := proofs[0].ToCircomVerifierProof(target1, foundValues[0], mt.Root(), levels)
	assert.NoError(s.T(), err)
	assert.False(s.T(), proof3.IsOld0)
}

func (s *MerkleTreeTestSuite) TestVerifyProof() {
	const levels = 10
	mt, _ := NewMerkleTree(s.db, levels)

	alice := testutils.NewKeypair()
	values := []int{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	done := make(chan bool, len(values))
	startProving := make(chan core.Node, len(values))
	for idx, value := range values {
		go func(v int, idx int) {
			salt := rand.Intn(100000)
			utxo := node.NewFungible(big.NewInt(int64(v)), alice.PublicKey, big.NewInt(int64(salt)))
			node, err := node.NewLeafNode(utxo)
			assert.NoError(s.T(), err)
			err = mt.AddLeaf(node)
			assert.NoError(s.T(), err)
			startProving <- node
			done <- true
			fmt.Printf("Added node %d\n", idx)
		}(value, idx)
	}

	go func() {
		// trigger the proving process after 1 nodes are added
		n := <-startProving
		fmt.Println("Received node for proving")

		target := n.Index().BigInt()
		root := mt.Root()
		p, _, err := mt.GenerateProofs([]*big.Int{target}, root)
		assert.NoError(s.T(), err)
		assert.True(s.T(), p[0].(*proof).existence)

		valid := VerifyProof(root, p[0], n)
		assert.True(s.T(), valid)
	}()

	for i := 0; i < len(values); i++ {
		<-done
	}

	fmt.Println("All done")
}

func (s *MerkleTreeTestSuite) TestSqliteStorage() {
	mt, err := NewMerkleTree(s.db, 10)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), mt)

	tokenId := big.NewInt(1001)
	uriString := "https://example.com/token/1001"
	assert.NoError(s.T(), err)
	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()

	utxo1 := node.NewNonFungible(tokenId, uriString, sender.PublicKey, salt1)
	n1, err := node.NewLeafNode(utxo1)
	assert.NoError(s.T(), err)
	err = mt.AddLeaf(n1)
	assert.NoError(s.T(), err)

	dbNode := core.SMTNode{RefKey: n1.Ref().Hex()}
	err = s.gormDB.Table(core.NodesTablePrefix + "test_1").First(&dbNode).Error
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), n1.Ref().Hex(), dbNode.RefKey)
}

func TestMerkleTreeSuite(t *testing.T) {
	suite.Run(t, new(MerkleTreeTestSuite))
}
