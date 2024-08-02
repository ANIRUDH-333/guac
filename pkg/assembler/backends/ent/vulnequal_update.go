// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnequal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilityid"
)

// VulnEqualUpdate is the builder for updating VulnEqual entities.
type VulnEqualUpdate struct {
	config
	hooks    []Hook
	mutation *VulnEqualMutation
}

// Where appends a list predicates to the VulnEqualUpdate builder.
func (veu *VulnEqualUpdate) Where(ps ...predicate.VulnEqual) *VulnEqualUpdate {
	veu.mutation.Where(ps...)
	return veu
}

// SetVulnID sets the "vuln_id" field.
func (veu *VulnEqualUpdate) SetVulnID(u uuid.UUID) *VulnEqualUpdate {
	veu.mutation.SetVulnID(u)
	return veu
}

// SetNillableVulnID sets the "vuln_id" field if the given value is not nil.
func (veu *VulnEqualUpdate) SetNillableVulnID(u *uuid.UUID) *VulnEqualUpdate {
	if u != nil {
		veu.SetVulnID(*u)
	}
	return veu
}

// SetEqualVulnID sets the "equal_vuln_id" field.
func (veu *VulnEqualUpdate) SetEqualVulnID(u uuid.UUID) *VulnEqualUpdate {
	veu.mutation.SetEqualVulnID(u)
	return veu
}

// SetNillableEqualVulnID sets the "equal_vuln_id" field if the given value is not nil.
func (veu *VulnEqualUpdate) SetNillableEqualVulnID(u *uuid.UUID) *VulnEqualUpdate {
	if u != nil {
		veu.SetEqualVulnID(*u)
	}
	return veu
}

// SetJustification sets the "justification" field.
func (veu *VulnEqualUpdate) SetJustification(s string) *VulnEqualUpdate {
	veu.mutation.SetJustification(s)
	return veu
}

// SetNillableJustification sets the "justification" field if the given value is not nil.
func (veu *VulnEqualUpdate) SetNillableJustification(s *string) *VulnEqualUpdate {
	if s != nil {
		veu.SetJustification(*s)
	}
	return veu
}

// SetOrigin sets the "origin" field.
func (veu *VulnEqualUpdate) SetOrigin(s string) *VulnEqualUpdate {
	veu.mutation.SetOrigin(s)
	return veu
}

// SetNillableOrigin sets the "origin" field if the given value is not nil.
func (veu *VulnEqualUpdate) SetNillableOrigin(s *string) *VulnEqualUpdate {
	if s != nil {
		veu.SetOrigin(*s)
	}
	return veu
}

// SetCollector sets the "collector" field.
func (veu *VulnEqualUpdate) SetCollector(s string) *VulnEqualUpdate {
	veu.mutation.SetCollector(s)
	return veu
}

// SetNillableCollector sets the "collector" field if the given value is not nil.
func (veu *VulnEqualUpdate) SetNillableCollector(s *string) *VulnEqualUpdate {
	if s != nil {
		veu.SetCollector(*s)
	}
	return veu
}

// SetDocumentRef sets the "document_ref" field.
func (veu *VulnEqualUpdate) SetDocumentRef(s string) *VulnEqualUpdate {
	veu.mutation.SetDocumentRef(s)
	return veu
}

// SetNillableDocumentRef sets the "document_ref" field if the given value is not nil.
func (veu *VulnEqualUpdate) SetNillableDocumentRef(s *string) *VulnEqualUpdate {
	if s != nil {
		veu.SetDocumentRef(*s)
	}
	return veu
}

// SetVulnerabilitiesHash sets the "vulnerabilities_hash" field.
func (veu *VulnEqualUpdate) SetVulnerabilitiesHash(s string) *VulnEqualUpdate {
	veu.mutation.SetVulnerabilitiesHash(s)
	return veu
}

// SetNillableVulnerabilitiesHash sets the "vulnerabilities_hash" field if the given value is not nil.
func (veu *VulnEqualUpdate) SetNillableVulnerabilitiesHash(s *string) *VulnEqualUpdate {
	if s != nil {
		veu.SetVulnerabilitiesHash(*s)
	}
	return veu
}

// SetVulnerabilityAID sets the "vulnerability_a" edge to the VulnerabilityID entity by ID.
func (veu *VulnEqualUpdate) SetVulnerabilityAID(id uuid.UUID) *VulnEqualUpdate {
	veu.mutation.SetVulnerabilityAID(id)
	return veu
}

// SetVulnerabilityA sets the "vulnerability_a" edge to the VulnerabilityID entity.
func (veu *VulnEqualUpdate) SetVulnerabilityA(v *VulnerabilityID) *VulnEqualUpdate {
	return veu.SetVulnerabilityAID(v.ID)
}

// SetVulnerabilityBID sets the "vulnerability_b" edge to the VulnerabilityID entity by ID.
func (veu *VulnEqualUpdate) SetVulnerabilityBID(id uuid.UUID) *VulnEqualUpdate {
	veu.mutation.SetVulnerabilityBID(id)
	return veu
}

// SetVulnerabilityB sets the "vulnerability_b" edge to the VulnerabilityID entity.
func (veu *VulnEqualUpdate) SetVulnerabilityB(v *VulnerabilityID) *VulnEqualUpdate {
	return veu.SetVulnerabilityBID(v.ID)
}

// Mutation returns the VulnEqualMutation object of the builder.
func (veu *VulnEqualUpdate) Mutation() *VulnEqualMutation {
	return veu.mutation
}

// ClearVulnerabilityA clears the "vulnerability_a" edge to the VulnerabilityID entity.
func (veu *VulnEqualUpdate) ClearVulnerabilityA() *VulnEqualUpdate {
	veu.mutation.ClearVulnerabilityA()
	return veu
}

// ClearVulnerabilityB clears the "vulnerability_b" edge to the VulnerabilityID entity.
func (veu *VulnEqualUpdate) ClearVulnerabilityB() *VulnEqualUpdate {
	veu.mutation.ClearVulnerabilityB()
	return veu
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (veu *VulnEqualUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, veu.sqlSave, veu.mutation, veu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (veu *VulnEqualUpdate) SaveX(ctx context.Context) int {
	affected, err := veu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (veu *VulnEqualUpdate) Exec(ctx context.Context) error {
	_, err := veu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (veu *VulnEqualUpdate) ExecX(ctx context.Context) {
	if err := veu.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (veu *VulnEqualUpdate) check() error {
	if veu.mutation.VulnerabilityACleared() && len(veu.mutation.VulnerabilityAIDs()) > 0 {
		return errors.New(`ent: clearing a required unique edge "VulnEqual.vulnerability_a"`)
	}
	if veu.mutation.VulnerabilityBCleared() && len(veu.mutation.VulnerabilityBIDs()) > 0 {
		return errors.New(`ent: clearing a required unique edge "VulnEqual.vulnerability_b"`)
	}
	return nil
}

func (veu *VulnEqualUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := veu.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(vulnequal.Table, vulnequal.Columns, sqlgraph.NewFieldSpec(vulnequal.FieldID, field.TypeUUID))
	if ps := veu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := veu.mutation.Justification(); ok {
		_spec.SetField(vulnequal.FieldJustification, field.TypeString, value)
	}
	if value, ok := veu.mutation.Origin(); ok {
		_spec.SetField(vulnequal.FieldOrigin, field.TypeString, value)
	}
	if value, ok := veu.mutation.Collector(); ok {
		_spec.SetField(vulnequal.FieldCollector, field.TypeString, value)
	}
	if value, ok := veu.mutation.DocumentRef(); ok {
		_spec.SetField(vulnequal.FieldDocumentRef, field.TypeString, value)
	}
	if value, ok := veu.mutation.VulnerabilitiesHash(); ok {
		_spec.SetField(vulnequal.FieldVulnerabilitiesHash, field.TypeString, value)
	}
	if veu.mutation.VulnerabilityACleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   vulnequal.VulnerabilityATable,
			Columns: []string{vulnequal.VulnerabilityAColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(vulnerabilityid.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := veu.mutation.VulnerabilityAIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   vulnequal.VulnerabilityATable,
			Columns: []string{vulnequal.VulnerabilityAColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(vulnerabilityid.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if veu.mutation.VulnerabilityBCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   vulnequal.VulnerabilityBTable,
			Columns: []string{vulnequal.VulnerabilityBColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(vulnerabilityid.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := veu.mutation.VulnerabilityBIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   vulnequal.VulnerabilityBTable,
			Columns: []string{vulnequal.VulnerabilityBColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(vulnerabilityid.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, veu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{vulnequal.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	veu.mutation.done = true
	return n, nil
}

// VulnEqualUpdateOne is the builder for updating a single VulnEqual entity.
type VulnEqualUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *VulnEqualMutation
}

// SetVulnID sets the "vuln_id" field.
func (veuo *VulnEqualUpdateOne) SetVulnID(u uuid.UUID) *VulnEqualUpdateOne {
	veuo.mutation.SetVulnID(u)
	return veuo
}

// SetNillableVulnID sets the "vuln_id" field if the given value is not nil.
func (veuo *VulnEqualUpdateOne) SetNillableVulnID(u *uuid.UUID) *VulnEqualUpdateOne {
	if u != nil {
		veuo.SetVulnID(*u)
	}
	return veuo
}

// SetEqualVulnID sets the "equal_vuln_id" field.
func (veuo *VulnEqualUpdateOne) SetEqualVulnID(u uuid.UUID) *VulnEqualUpdateOne {
	veuo.mutation.SetEqualVulnID(u)
	return veuo
}

// SetNillableEqualVulnID sets the "equal_vuln_id" field if the given value is not nil.
func (veuo *VulnEqualUpdateOne) SetNillableEqualVulnID(u *uuid.UUID) *VulnEqualUpdateOne {
	if u != nil {
		veuo.SetEqualVulnID(*u)
	}
	return veuo
}

// SetJustification sets the "justification" field.
func (veuo *VulnEqualUpdateOne) SetJustification(s string) *VulnEqualUpdateOne {
	veuo.mutation.SetJustification(s)
	return veuo
}

// SetNillableJustification sets the "justification" field if the given value is not nil.
func (veuo *VulnEqualUpdateOne) SetNillableJustification(s *string) *VulnEqualUpdateOne {
	if s != nil {
		veuo.SetJustification(*s)
	}
	return veuo
}

// SetOrigin sets the "origin" field.
func (veuo *VulnEqualUpdateOne) SetOrigin(s string) *VulnEqualUpdateOne {
	veuo.mutation.SetOrigin(s)
	return veuo
}

// SetNillableOrigin sets the "origin" field if the given value is not nil.
func (veuo *VulnEqualUpdateOne) SetNillableOrigin(s *string) *VulnEqualUpdateOne {
	if s != nil {
		veuo.SetOrigin(*s)
	}
	return veuo
}

// SetCollector sets the "collector" field.
func (veuo *VulnEqualUpdateOne) SetCollector(s string) *VulnEqualUpdateOne {
	veuo.mutation.SetCollector(s)
	return veuo
}

// SetNillableCollector sets the "collector" field if the given value is not nil.
func (veuo *VulnEqualUpdateOne) SetNillableCollector(s *string) *VulnEqualUpdateOne {
	if s != nil {
		veuo.SetCollector(*s)
	}
	return veuo
}

// SetDocumentRef sets the "document_ref" field.
func (veuo *VulnEqualUpdateOne) SetDocumentRef(s string) *VulnEqualUpdateOne {
	veuo.mutation.SetDocumentRef(s)
	return veuo
}

// SetNillableDocumentRef sets the "document_ref" field if the given value is not nil.
func (veuo *VulnEqualUpdateOne) SetNillableDocumentRef(s *string) *VulnEqualUpdateOne {
	if s != nil {
		veuo.SetDocumentRef(*s)
	}
	return veuo
}

// SetVulnerabilitiesHash sets the "vulnerabilities_hash" field.
func (veuo *VulnEqualUpdateOne) SetVulnerabilitiesHash(s string) *VulnEqualUpdateOne {
	veuo.mutation.SetVulnerabilitiesHash(s)
	return veuo
}

// SetNillableVulnerabilitiesHash sets the "vulnerabilities_hash" field if the given value is not nil.
func (veuo *VulnEqualUpdateOne) SetNillableVulnerabilitiesHash(s *string) *VulnEqualUpdateOne {
	if s != nil {
		veuo.SetVulnerabilitiesHash(*s)
	}
	return veuo
}

// SetVulnerabilityAID sets the "vulnerability_a" edge to the VulnerabilityID entity by ID.
func (veuo *VulnEqualUpdateOne) SetVulnerabilityAID(id uuid.UUID) *VulnEqualUpdateOne {
	veuo.mutation.SetVulnerabilityAID(id)
	return veuo
}

// SetVulnerabilityA sets the "vulnerability_a" edge to the VulnerabilityID entity.
func (veuo *VulnEqualUpdateOne) SetVulnerabilityA(v *VulnerabilityID) *VulnEqualUpdateOne {
	return veuo.SetVulnerabilityAID(v.ID)
}

// SetVulnerabilityBID sets the "vulnerability_b" edge to the VulnerabilityID entity by ID.
func (veuo *VulnEqualUpdateOne) SetVulnerabilityBID(id uuid.UUID) *VulnEqualUpdateOne {
	veuo.mutation.SetVulnerabilityBID(id)
	return veuo
}

// SetVulnerabilityB sets the "vulnerability_b" edge to the VulnerabilityID entity.
func (veuo *VulnEqualUpdateOne) SetVulnerabilityB(v *VulnerabilityID) *VulnEqualUpdateOne {
	return veuo.SetVulnerabilityBID(v.ID)
}

// Mutation returns the VulnEqualMutation object of the builder.
func (veuo *VulnEqualUpdateOne) Mutation() *VulnEqualMutation {
	return veuo.mutation
}

// ClearVulnerabilityA clears the "vulnerability_a" edge to the VulnerabilityID entity.
func (veuo *VulnEqualUpdateOne) ClearVulnerabilityA() *VulnEqualUpdateOne {
	veuo.mutation.ClearVulnerabilityA()
	return veuo
}

// ClearVulnerabilityB clears the "vulnerability_b" edge to the VulnerabilityID entity.
func (veuo *VulnEqualUpdateOne) ClearVulnerabilityB() *VulnEqualUpdateOne {
	veuo.mutation.ClearVulnerabilityB()
	return veuo
}

// Where appends a list predicates to the VulnEqualUpdate builder.
func (veuo *VulnEqualUpdateOne) Where(ps ...predicate.VulnEqual) *VulnEqualUpdateOne {
	veuo.mutation.Where(ps...)
	return veuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (veuo *VulnEqualUpdateOne) Select(field string, fields ...string) *VulnEqualUpdateOne {
	veuo.fields = append([]string{field}, fields...)
	return veuo
}

// Save executes the query and returns the updated VulnEqual entity.
func (veuo *VulnEqualUpdateOne) Save(ctx context.Context) (*VulnEqual, error) {
	return withHooks(ctx, veuo.sqlSave, veuo.mutation, veuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (veuo *VulnEqualUpdateOne) SaveX(ctx context.Context) *VulnEqual {
	node, err := veuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (veuo *VulnEqualUpdateOne) Exec(ctx context.Context) error {
	_, err := veuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (veuo *VulnEqualUpdateOne) ExecX(ctx context.Context) {
	if err := veuo.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (veuo *VulnEqualUpdateOne) check() error {
	if veuo.mutation.VulnerabilityACleared() && len(veuo.mutation.VulnerabilityAIDs()) > 0 {
		return errors.New(`ent: clearing a required unique edge "VulnEqual.vulnerability_a"`)
	}
	if veuo.mutation.VulnerabilityBCleared() && len(veuo.mutation.VulnerabilityBIDs()) > 0 {
		return errors.New(`ent: clearing a required unique edge "VulnEqual.vulnerability_b"`)
	}
	return nil
}

func (veuo *VulnEqualUpdateOne) sqlSave(ctx context.Context) (_node *VulnEqual, err error) {
	if err := veuo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(vulnequal.Table, vulnequal.Columns, sqlgraph.NewFieldSpec(vulnequal.FieldID, field.TypeUUID))
	id, ok := veuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "VulnEqual.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := veuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, vulnequal.FieldID)
		for _, f := range fields {
			if !vulnequal.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != vulnequal.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := veuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := veuo.mutation.Justification(); ok {
		_spec.SetField(vulnequal.FieldJustification, field.TypeString, value)
	}
	if value, ok := veuo.mutation.Origin(); ok {
		_spec.SetField(vulnequal.FieldOrigin, field.TypeString, value)
	}
	if value, ok := veuo.mutation.Collector(); ok {
		_spec.SetField(vulnequal.FieldCollector, field.TypeString, value)
	}
	if value, ok := veuo.mutation.DocumentRef(); ok {
		_spec.SetField(vulnequal.FieldDocumentRef, field.TypeString, value)
	}
	if value, ok := veuo.mutation.VulnerabilitiesHash(); ok {
		_spec.SetField(vulnequal.FieldVulnerabilitiesHash, field.TypeString, value)
	}
	if veuo.mutation.VulnerabilityACleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   vulnequal.VulnerabilityATable,
			Columns: []string{vulnequal.VulnerabilityAColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(vulnerabilityid.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := veuo.mutation.VulnerabilityAIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   vulnequal.VulnerabilityATable,
			Columns: []string{vulnequal.VulnerabilityAColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(vulnerabilityid.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if veuo.mutation.VulnerabilityBCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   vulnequal.VulnerabilityBTable,
			Columns: []string{vulnequal.VulnerabilityBColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(vulnerabilityid.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := veuo.mutation.VulnerabilityBIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   vulnequal.VulnerabilityBTable,
			Columns: []string{vulnequal.VulnerabilityBColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(vulnerabilityid.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &VulnEqual{config: veuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, veuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{vulnequal.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	veuo.mutation.done = true
	return _node, nil
}
