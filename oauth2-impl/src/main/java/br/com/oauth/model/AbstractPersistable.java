package br.com.oauth.model;

import static java.util.Objects.hash;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.MappedSuperclass;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.springframework.data.annotation.Id;
import org.springframework.data.domain.Persistable;

@MappedSuperclass
public abstract class AbstractPersistable<T extends Serializable> implements Persistable<T> {

    /**************************************************************/
    /************************* ATRIBUTOS **************************/
    /**************************************************************/

    /**
     * SERIAL VERSION UID.
     */
    private static final long serialVersionUID = 1L;

    /** O(a) id. */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false)
    private T id;

    /**************************************************************/
    /********************** FUNCIONALIDADES ***********************/
    /**************************************************************/

    /*
     * (non-Javadoc)
     * 
     * @see br.com.silvanopessoa.rest.api.model.base.Persistable#isNew()
     */
    public boolean isNew() {
        return null == getId();
    }

    /**************************************************************/
    /************************** GET/SET ***************************/
    /**************************************************************/

    /**
     * Obtém o valor do(a)(s) id.
     *
     * @author gabriel.marciano
     * @return the id
     */
    public T getId() {
        return id;
    }

    /**
     * Sets the id.
     *
     * @param id
     *            the new id
     */
    public void setId(final T id) {
        this.id = id;
    }

    /**************************************************************/
    /****************** EQUALS/HASHCODE/TOSTRING ******************/
    /**************************************************************/

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
      return hash(this.id);
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @SuppressWarnings("unchecked")
    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof AbstractPersistable)) {
            return false;
        }
        AbstractPersistable<T> other = (AbstractPersistable<T>) obj;
        return new EqualsBuilder().append(this.id, other.id).isEquals();
    }

}